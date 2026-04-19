#include <array>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>

#include "cppminhook/diagnostics.h"
#include "cppminhook/hook_engine.h"

namespace {

using AddFunction = int(*)(int, int);
using GetTickCountFunction = unsigned long (WINAPI*)();

AddFunction g_originalAdd = nullptr;
AddFunction g_originalAdd2 = nullptr;
GetTickCountFunction g_originalGetTickCount = nullptr;

int detour_add(int left, int right) {
    const auto originalResult = g_originalAdd != nullptr ? g_originalAdd(left, right) : 0;
    return originalResult + 100;
}

int detour_add2(int left, int right) {
    const auto originalResult = g_originalAdd2 != nullptr ? g_originalAdd2(left, right) : 0;
    return originalResult + 200;
}

unsigned long WINAPI detour_get_tick_count() {
    const unsigned long original = g_originalGetTickCount != nullptr ? g_originalGetTickCount() : 0UL;
    return original + 1000UL;
}

class ExecutableBlock {
public:
    explicit ExecutableBlock(const std::byte* bytes, std::size_t size)
        : size_(size) {
        buffer_ = ::VirtualAlloc(nullptr, size_, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (buffer_ != nullptr) {
            std::memcpy(buffer_, bytes, size_);
        }
    }

    ~ExecutableBlock() {
        if (buffer_ != nullptr) {
            ::VirtualFree(buffer_, 0, MEM_RELEASE);
        }
    }

    ExecutableBlock(const ExecutableBlock&) = delete;
    ExecutableBlock& operator=(const ExecutableBlock&) = delete;

    [[nodiscard]] void* data() const noexcept {
        return buffer_;
    }

    void release() noexcept {
        if (buffer_ != nullptr) {
            ::VirtualFree(buffer_, 0, MEM_RELEASE);
            buffer_ = nullptr;
            size_ = 0;
        }
    }

private:
    void* buffer_ = nullptr;
    std::size_t size_ = 0;
};

[[nodiscard]] std::array<std::byte, 16> sample_function_bytes() {
#if defined(_M_X64) || defined(__x86_64__)
    return {
        std::byte{0x89}, std::byte{0xC8},
        std::byte{0x01}, std::byte{0xD0},
        std::byte{0x83}, std::byte{0xC0}, std::byte{0x01},
        std::byte{0x83}, std::byte{0xC0}, std::byte{0x02},
        std::byte{0x90},
        std::byte{0x90},
        std::byte{0x90},
        std::byte{0xC3}
    };
#else
    return {
        std::byte{0x8B}, std::byte{0x44}, std::byte{0x24}, std::byte{0x04},
        std::byte{0x03}, std::byte{0x44}, std::byte{0x24}, std::byte{0x08},
        std::byte{0x83}, std::byte{0xC0}, std::byte{0x03},
        std::byte{0xC3},
        std::byte{0x90},
        std::byte{0x90},
        std::byte{0x90},
        std::byte{0x90}
    };
#endif
}

bool require(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        return false;
    }

    return true;
}

bool test_lifecycle() {
    cppminhook::HookEngine engine;
    return require(engine.initialize() == cppminhook::Status::ok, "initialize succeeds") &&
           require(engine.initialize() == cppminhook::Status::already_initialized, "double initialize reports already_initialized") &&
           require(engine.uninitialize() == cppminhook::Status::ok, "uninitialize succeeds");
}

bool test_queue_and_trampoline() {
    const auto bytes = sample_function_bytes();
    ExecutableBlock block(bytes.data(), bytes.size());
    if (!require(block.data() != nullptr, "executable block allocated")) {
        return false;
    }

    cppminhook::HookEngine engine;
    if (!require(engine.initialize() == cppminhook::Status::ok, "engine initializes")) {
        return false;
    }

    auto function = reinterpret_cast<AddFunction>(block.data());
    if (!require(function(3, 4) == 10, "original function returns expected value")) {
        return false;
    }

    cppminhook::Hook* hook = nullptr;
    if (!require(engine.create_hook(block.data(), reinterpret_cast<void*>(&detour_add), &hook) == cppminhook::Status::ok,
                 "hook is created")) {
        return false;
    }

    if (!require(hook != nullptr, "hook pointer returned")) {
        return false;
    }

    g_originalAdd = hook->original<AddFunction>();
    if (!require(engine.queue_enable_all() == cppminhook::Status::ok, "queue_enable_all succeeds")) {
        return false;
    }

    if (!require(engine.apply_queued() == cppminhook::Status::ok, "apply_queued enables hook")) {
        return false;
    }

    if (!require(function(3, 4) == 110, "detoured function calls original trampoline")) {
        return false;
    }

    if (!require(engine.queue_disable(block.data()) == cppminhook::Status::ok, "queue_disable succeeds")) {
        return false;
    }

    if (!require(engine.apply_queued() == cppminhook::Status::ok, "apply_queued disables hook")) {
        return false;
    }

    if (!require(function(3, 4) == 10, "original function restored")) {
        return false;
    }

    return require(engine.uninitialize() == cppminhook::Status::ok, "engine uninitializes after queue test");
}

bool test_api_resolution() {
    cppminhook::HookEngine engine;
    if (!require(engine.initialize() == cppminhook::Status::ok, "engine initializes for api resolution")) {
        return false;
    }

    void* target = nullptr;
    if (!require(engine.resolve_api_target(L"kernel32.dll", "GetTickCount", &target) == cppminhook::Status::ok,
                 "resolve_api_target finds a known export")) {
        return false;
    }

    if (!require(target != nullptr, "resolved api target is non-null")) {
        return false;
    }

    if (!require(engine.resolve_api_target(L"missing-module.dll", "GetTickCount", &target) == cppminhook::Status::module_not_found,
                 "missing module reports module_not_found")) {
        return false;
    }

    if (!require(engine.resolve_api_target(L"kernel32.dll", "DefinitelyMissingExport", &target) == cppminhook::Status::function_not_found,
                 "missing export reports function_not_found")) {
        return false;
    }

    return require(engine.uninitialize() == cppminhook::Status::ok, "engine uninitializes after api resolution test");
}

bool test_unsupported_prologue() {
    const std::array<std::byte, 16> bytes = {
        std::byte{0xEB}, std::byte{0x00},
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
        std::byte{0x90}, std::byte{0xC3}
    };

    ExecutableBlock block(bytes.data(), bytes.size());
    if (!require(block.data() != nullptr, "unsupported block allocated")) {
        return false;
    }

    cppminhook::HookEngine engine;
    if (!require(engine.initialize() == cppminhook::Status::ok, "engine initializes for unsupported test")) {
        return false;
    }

    cppminhook::Hook* hook = nullptr;
    const auto status = engine.create_hook(block.data(), reinterpret_cast<void*>(&detour_add), &hook);
    if (!require(status == cppminhook::Status::unsupported_target, "unsupported prologue is rejected")) {
        return false;
    }

    const auto diag = cppminhook::last_diagnostic();
    if (!require(diag.status == cppminhook::Status::unsupported_target, "diagnostic captures unsupported_target")) {
        return false;
    }

    return require(engine.uninitialize() == cppminhook::Status::ok, "engine uninitializes after unsupported test");
}

bool test_stress_enable_disable() {
    const auto bytes = sample_function_bytes();
    ExecutableBlock block(bytes.data(), bytes.size());
    if (!require(block.data() != nullptr, "stress block allocated")) {
        return false;
    }

    cppminhook::HookEngine engine;
    if (!require(engine.initialize() == cppminhook::Status::ok, "engine initializes for stress test")) {
        return false;
    }

    auto function = reinterpret_cast<AddFunction>(block.data());
    cppminhook::Hook* hook = nullptr;
    if (!require(engine.create_hook(block.data(), reinterpret_cast<void*>(&detour_add), &hook) == cppminhook::Status::ok,
                 "stress hook created")) {
        return false;
    }

    g_originalAdd = hook->original<AddFunction>();

    for (int iteration = 0; iteration < 100; ++iteration) {
        if (!require(hook->enable() == cppminhook::Status::ok, "stress enable succeeds")) {
            return false;
        }

        if (!require(function(2, 3) == 108, "stress detoured value expected")) {
            return false;
        }

        if (!require(hook->disable() == cppminhook::Status::ok, "stress disable succeeds")) {
            return false;
        }

        if (!require(function(2, 3) == 8, "stress restored value expected")) {
            return false;
        }
    }

    return require(engine.uninitialize() == cppminhook::Status::ok, "engine uninitializes after stress test");
}

bool test_apply_queued_rollback() {
    const auto bytes = sample_function_bytes();
    ExecutableBlock block1(bytes.data(), bytes.size());
    ExecutableBlock block2(bytes.data(), bytes.size());
    if (!require(block1.data() != nullptr && block2.data() != nullptr, "rollback blocks allocated")) {
        return false;
    }

    cppminhook::HookEngine engine;
    if (!require(engine.initialize() == cppminhook::Status::ok, "engine initializes for rollback test")) {
        return false;
    }

    auto function1 = reinterpret_cast<AddFunction>(block1.data());

    cppminhook::Hook* hook1 = nullptr;
    cppminhook::Hook* hook2 = nullptr;
    if (!require(engine.create_hook(block1.data(), reinterpret_cast<void*>(&detour_add), &hook1) == cppminhook::Status::ok,
                 "rollback hook1 created")) {
        return false;
    }

    if (!require(engine.create_hook(block2.data(), reinterpret_cast<void*>(&detour_add2), &hook2) == cppminhook::Status::ok,
                 "rollback hook2 created")) {
        return false;
    }

    g_originalAdd = hook1->original<AddFunction>();
    g_originalAdd2 = hook2->original<AddFunction>();

    if (!require(engine.queue_enable_all() == cppminhook::Status::ok, "rollback queue_enable_all succeeds")) {
        return false;
    }

    block2.release();
    const auto applyStatus = engine.apply_queued();
    if (!require(applyStatus == cppminhook::Status::memory_protection_failed, "apply_queued reports memory protection failure")) {
        return false;
    }

    if (!require(function1(3, 4) == 10, "rollback restores first hook state after failure")) {
        return false;
    }

    const auto diag = cppminhook::last_diagnostic();
    if (!require(diag.status == cppminhook::Status::memory_protection_failed, "diagnostic captures apply_queued failure")) {
        return false;
    }

    return require(engine.uninitialize() == cppminhook::Status::ok, "engine uninitializes after rollback test");
}

bool test_transaction_api() {
    const auto bytes = sample_function_bytes();
    ExecutableBlock block(bytes.data(), bytes.size());
    if (!require(block.data() != nullptr, "transaction block allocated")) {
        return false;
    }

    cppminhook::HookEngine engine;
    if (!require(engine.initialize() == cppminhook::Status::ok, "engine initializes for transaction test")) {
        return false;
    }

    cppminhook::Hook* hook = nullptr;
    if (!require(engine.create_hook(block.data(), reinterpret_cast<void*>(&detour_add), &hook) == cppminhook::Status::ok,
                 "transaction hook created")) {
        return false;
    }

    g_originalAdd = hook->original<AddFunction>();

    if (!require(engine.begin_transaction() == cppminhook::Status::ok, "begin_transaction succeeds")) {
        return false;
    }

    if (!require(engine.transaction_active(), "transaction_active true after begin")) {
        return false;
    }

    if (!require(engine.queue_enable(block.data()) == cppminhook::Status::ok, "queue_enable in transaction succeeds")) {
        return false;
    }

    if (!require(engine.abort_transaction() == cppminhook::Status::ok, "abort_transaction succeeds")) {
        return false;
    }

    if (!require(!engine.transaction_active(), "transaction_active false after abort")) {
        return false;
    }

    auto function = reinterpret_cast<AddFunction>(block.data());
    if (!require(function(3, 4) == 10, "abort clears queued effects")) {
        return false;
    }

    if (!require(engine.begin_transaction() == cppminhook::Status::ok, "second begin_transaction succeeds")) {
        return false;
    }

    if (!require(engine.queue_enable_all() == cppminhook::Status::ok, "queue_enable_all in transaction succeeds")) {
        return false;
    }

    if (!require(engine.commit_transaction() == cppminhook::Status::ok, "commit_transaction succeeds")) {
        return false;
    }

    if (!require(function(3, 4) == 110, "transaction commit enables hook")) {
        return false;
    }

    return require(engine.uninitialize() == cppminhook::Status::ok, "engine uninitializes after transaction test");
}

bool test_decoder_backend_policy() {
    const auto bytes = sample_function_bytes();
    ExecutableBlock block(bytes.data(), bytes.size());
    if (!require(block.data() != nullptr, "decoder policy block allocated")) {
        return false;
    }

    cppminhook::HookEngine engine;
    if (!require(engine.initialize() == cppminhook::Status::ok, "engine initializes for decoder policy")) {
        return false;
    }

    cppminhook::HookOptions unavailableBackendOptions{};
    unavailableBackendOptions.decoderBackend = cppminhook::DecoderBackend::capstone;

    cppminhook::Hook* hook = nullptr;
    const auto unavailableStatus = engine.create_hook(block.data(), reinterpret_cast<void*>(&detour_add), unavailableBackendOptions, &hook);
    if (!require(unavailableStatus == cppminhook::Status::unsupported_target, "unavailable backend reports unsupported_target")) {
        return false;
    }

    cppminhook::HookOptions lenientOptions{};
    lenientOptions.strictMode = false;
    lenientOptions.failOnUnknownInstruction = false;
    const auto lenientStatus = engine.create_hook(block.data(), reinterpret_cast<void*>(&detour_add), lenientOptions, &hook);
    if (!require(lenientStatus == cppminhook::Status::ok, "lenient options can create hook")) {
        return false;
    }

    return require(engine.uninitialize() == cppminhook::Status::ok, "engine uninitializes after decoder policy test");
}

bool test_relocation_fixtures() {
    struct Fixture {
        std::array<std::byte, 16> bytes;
        cppminhook::Status expected;
        const char* name;
    };

    const std::vector<Fixture> fixtures = {
        {
            {
                std::byte{0xE8}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
                std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
                std::byte{0xC3}
            },
            cppminhook::Status::ok,
            "rel32 call fixture"
        },
        {
            {
                std::byte{0xE9}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
                std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
                std::byte{0xC3}
            },
            cppminhook::Status::ok,
            "rel32 jmp fixture"
        },
        {
            {
                std::byte{0xEB}, std::byte{0x00},
                std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
                std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
                std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
                std::byte{0x90}, std::byte{0xC3}
            },
            cppminhook::Status::unsupported_target,
            "short jump unsupported fixture"
        }
    };

    cppminhook::HookEngine engine;
    if (!require(engine.initialize() == cppminhook::Status::ok, "engine initializes for relocation fixtures")) {
        return false;
    }

    for (const auto& fixture : fixtures) {
        ExecutableBlock block(fixture.bytes.data(), fixture.bytes.size());
        if (!require(block.data() != nullptr, fixture.name)) {
            return false;
        }

        cppminhook::Hook* hook = nullptr;
        const auto status = engine.create_hook(block.data(), reinterpret_cast<void*>(&detour_add), &hook);
        if (!require(status == fixture.expected, fixture.name)) {
            return false;
        }

        if (status == cppminhook::Status::ok) {
            if (!require(engine.remove_hook(block.data()) == cppminhook::Status::ok, "fixture hook removed")) {
                return false;
            }
        }
    }

    return require(engine.uninitialize() == cppminhook::Status::ok, "engine uninitializes after relocation fixtures");
}

bool test_short_branch_widening_enabled() {
    const std::array<std::byte, 16> bytes = {
        std::byte{0xEB}, std::byte{0x05},
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
        std::byte{0x31}, std::byte{0xC0},
        std::byte{0x83}, std::byte{0xC0}, std::byte{0x07},
        std::byte{0x90}, std::byte{0x90},
        std::byte{0xC3},
        std::byte{0x90}
    };

    ExecutableBlock block(bytes.data(), bytes.size());
    if (!require(block.data() != nullptr, "short-branch widening block allocated")) {
        return false;
    }

    cppminhook::HookEngine engine;
    if (!require(engine.initialize() == cppminhook::Status::ok, "engine initializes for short-branch widening")) {
        return false;
    }

    cppminhook::HookOptions options{};
    options.allowShortBranchWidening = true;

    cppminhook::Hook* hook = nullptr;
    const auto status = engine.create_hook(block.data(), reinterpret_cast<void*>(&detour_add), options, &hook);
    if (!require(status == cppminhook::Status::ok, "short-branch widening creates hook")) {
        return false;
    }

    return require(engine.uninitialize() == cppminhook::Status::ok, "engine uninitializes after short-branch widening");
}

bool test_rip_relative_fixture() {
#if defined(_M_X64) || defined(__x86_64__)
    const std::array<std::byte, 16> bytes = {
        std::byte{0x8B}, std::byte{0x05}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x83}, std::byte{0xC0}, std::byte{0x01},
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
        std::byte{0xC3},
        std::byte{0x90}
    };
#else
    const std::array<std::byte, 16> bytes = sample_function_bytes();
#endif

    ExecutableBlock block(bytes.data(), bytes.size());
    if (!require(block.data() != nullptr, "rip-relative block allocated")) {
        return false;
    }

    cppminhook::HookEngine engine;
    if (!require(engine.initialize() == cppminhook::Status::ok, "engine initializes for rip-relative fixture")) {
        return false;
    }

    cppminhook::Hook* hook = nullptr;
    const auto status = engine.create_hook(block.data(), reinterpret_cast<void*>(&detour_add), &hook);
    if (!require(status == cppminhook::Status::ok, "rip-relative fixture creates hook")) {
        return false;
    }

    return require(engine.uninitialize() == cppminhook::Status::ok, "engine uninitializes after rip-relative fixture");
}

bool test_create_hook_api_integration() {
    cppminhook::HookEngine engine;
    if (!require(engine.initialize() == cppminhook::Status::ok, "engine initializes for api hook integration")) {
        return false;
    }

    cppminhook::HookOptions options{};
    options.resolveForwardedExports = true;
    options.loadModuleIfNeeded = true;

    cppminhook::Hook* hook = nullptr;
    void* resolvedTarget = nullptr;
    const auto createStatus = engine.create_hook_api(
        L"kernel32.dll",
        "GetTickCount",
        reinterpret_cast<void*>(&detour_get_tick_count),
        options,
        &hook,
        &resolvedTarget);
    if (!require(createStatus == cppminhook::Status::ok, "create_hook_api succeeds for GetTickCount")) {
        return false;
    }

    if (!require(hook != nullptr && resolvedTarget != nullptr, "create_hook_api returns hook and target")) {
        return false;
    }

    g_originalGetTickCount = hook->original<GetTickCountFunction>();
    if (!require(engine.queue_enable_all() == cppminhook::Status::ok, "queue_enable_all succeeds for api hook")) {
        return false;
    }

    if (!require(engine.apply_queued() == cppminhook::Status::ok, "apply_queued enables api hook")) {
        return false;
    }

    const unsigned long hookedValue = ::GetTickCount();
    const unsigned long baselineValue = g_originalGetTickCount != nullptr ? g_originalGetTickCount() : 0UL;
    if (!require(hookedValue >= baselineValue + 500UL, "hooked GetTickCount value includes detour offset")) {
        return false;
    }

    if (!require(engine.queue_disable_all() == cppminhook::Status::ok, "queue_disable_all succeeds for api hook")) {
        return false;
    }

    if (!require(engine.apply_queued() == cppminhook::Status::ok, "apply_queued disables api hook")) {
        return false;
    }

    return require(engine.uninitialize() == cppminhook::Status::ok, "engine uninitializes after api hook integration");
}

bool test_fuzz_like_robustness() {
    cppminhook::HookEngine engine;
    if (!require(engine.initialize() == cppminhook::Status::ok, "engine initializes for fuzz loop")) {
        return false;
    }

    std::mt19937 generator(1337U);
    std::uniform_int_distribution<int> byteDistribution(0, 255);

    cppminhook::HookOptions fuzzOptions{};
    fuzzOptions.strictMode = false;
    fuzzOptions.failOnUnknownInstruction = false;

    for (int iteration = 0; iteration < 300; ++iteration) {
        std::array<std::byte, 16> bytes{};
        for (std::size_t i = 0; i < bytes.size() - 1; ++i) {
            bytes[i] = static_cast<std::byte>(byteDistribution(generator));
        }
        bytes[bytes.size() - 1] = std::byte{0xC3};

        ExecutableBlock block(bytes.data(), bytes.size());
        if (!require(block.data() != nullptr, "fuzz block allocation")) {
            return false;
        }

        cppminhook::Hook* hook = nullptr;
        const auto status = engine.create_hook(block.data(), reinterpret_cast<void*>(&detour_add), fuzzOptions, &hook);
        if (status == cppminhook::Status::ok) {
            if (!require(engine.remove_hook(block.data()) == cppminhook::Status::ok, "fuzz hook remove")) {
                return false;
            }
        }
    }

    return require(engine.uninitialize() == cppminhook::Status::ok, "engine uninitializes after fuzz loop");
}

bool test_transaction_edge_cases() {
    cppminhook::HookEngine engine;

    if (!require(engine.begin_transaction() == cppminhook::Status::not_initialized,
                 "begin_transaction requires initialization")) {
        return false;
    }

    if (!require(engine.initialize() == cppminhook::Status::ok, "engine initializes for transaction edge cases")) {
        return false;
    }

    if (!require(engine.commit_transaction() == cppminhook::Status::already_disabled,
                 "commit_transaction without begin reports already_disabled")) {
        return false;
    }

    if (!require(engine.abort_transaction() == cppminhook::Status::already_disabled,
                 "abort_transaction without begin reports already_disabled")) {
        return false;
    }

    if (!require(engine.begin_transaction() == cppminhook::Status::ok, "begin_transaction succeeds")) {
        return false;
    }

    if (!require(engine.begin_transaction() == cppminhook::Status::already_enabled,
                 "double begin_transaction reports already_enabled")) {
        return false;
    }

    if (!require(engine.abort_transaction() == cppminhook::Status::ok, "abort_transaction succeeds after begin")) {
        return false;
    }

    return require(engine.uninitialize() == cppminhook::Status::ok,
                   "engine uninitializes after transaction edge cases");
}

bool test_diagnostic_formatting() {
    cppminhook::DiagnosticContext context{};
    context.status = cppminhook::Status::unsupported_target;
    context.systemError = 5;
    context.operation = "unit.test";
    context.phase = "create";
    context.targetAddress = reinterpret_cast<void*>(0x1000);
    context.detourAddress = reinterpret_cast<void*>(0x2000);
    context.patchSize = 14;

    cppminhook::report_diagnostic(context);
    const std::string formatted = cppminhook::format_last_diagnostic();

    if (!require(formatted.find("unsupported_target") != std::string::npos, "formatted diagnostic includes status")) {
        return false;
    }

    if (!require(formatted.find("unit.test") != std::string::npos, "formatted diagnostic includes operation")) {
        return false;
    }

    if (!require(formatted.find("patchSize=14") != std::string::npos, "formatted diagnostic includes patch size")) {
        return false;
    }

    const std::string json = cppminhook::format_last_diagnostic_json();
    if (!require(json.find("\"status\":\"unsupported_target\"") != std::string::npos,
                 "json diagnostic includes status")) {
        return false;
    }

    if (!require(json.find("\"code\":\"") != std::string::npos,
                 "json diagnostic includes code")) {
        return false;
    }

    cppminhook::clear_diagnostic();
    return true;
}

} // namespace

int main() {
    const bool ok = test_lifecycle() &&
                    test_queue_and_trampoline() &&
                    test_api_resolution() &&
                    test_unsupported_prologue() &&
                    test_stress_enable_disable() &&
                    test_apply_queued_rollback() &&
                    test_transaction_api() &&
                    test_transaction_edge_cases() &&
                    test_decoder_backend_policy() &&
                    test_relocation_fixtures() &&
                    test_short_branch_widening_enabled() &&
                    test_rip_relative_fixture() &&
                    test_fuzz_like_robustness() &&
                    test_create_hook_api_integration() &&
                    test_diagnostic_formatting();
    if (!ok) {
        return EXIT_FAILURE;
    }

    std::cout << "All tests passed\n";
    return EXIT_SUCCESS;
}

