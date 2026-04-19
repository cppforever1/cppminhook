#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <windows.h>

#include "cppminhook/hook_engine.h"

namespace {

using AddFunction = int(*)(int, int);
AddFunction g_originalAdd = nullptr;

int detour_add(int left, int right) {
    const auto original = g_originalAdd != nullptr ? g_originalAdd(left, right) : 0;
    return original + 1;
}

class ExecutableBlock {
public:
    explicit ExecutableBlock(const std::byte* bytes, std::size_t size) : size_(size) {
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

    [[nodiscard]] void* data() const noexcept { return buffer_; }

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

} // namespace

int main() {
    constexpr int iterations = 1'000'000;

    const auto bytes = sample_function_bytes();
    ExecutableBlock block(bytes.data(), bytes.size());
    if (block.data() == nullptr) {
        std::cerr << "Unable to allocate executable block\n";
        return EXIT_FAILURE;
    }

    auto function = reinterpret_cast<AddFunction>(block.data());

    volatile int sink = 0;
    auto baselineStart = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        sink += function(i, i + 1);
    }
    auto baselineEnd = std::chrono::high_resolution_clock::now();

    cppminhook::HookEngine engine;
    if (engine.initialize() != cppminhook::Status::ok) {
        std::cerr << "Engine initialization failed\n";
        return EXIT_FAILURE;
    }

    cppminhook::Hook* hook = nullptr;
    if (engine.create_hook(block.data(), reinterpret_cast<void*>(&detour_add), &hook) != cppminhook::Status::ok || hook == nullptr) {
        std::cerr << "Hook creation failed\n";
        return EXIT_FAILURE;
    }

    g_originalAdd = hook->original<AddFunction>();
    if (hook->enable() != cppminhook::Status::ok) {
        std::cerr << "Hook enable failed\n";
        return EXIT_FAILURE;
    }

    auto hookedStart = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        sink += function(i, i + 1);
    }
    auto hookedEnd = std::chrono::high_resolution_clock::now();

    if (engine.uninitialize() != cppminhook::Status::ok) {
        std::cerr << "Engine uninitialize failed\n";
        return EXIT_FAILURE;
    }

    const auto baselineNs = std::chrono::duration_cast<std::chrono::nanoseconds>(baselineEnd - baselineStart).count();
    const auto hookedNs = std::chrono::duration_cast<std::chrono::nanoseconds>(hookedEnd - hookedStart).count();

    std::cout << "sink=" << sink << '\n';
    std::cout << "baseline_ns_total=" << baselineNs << '\n';
    std::cout << "hooked_ns_total=" << hookedNs << '\n';
    std::cout << "baseline_ns_per_call=" << static_cast<double>(baselineNs) / iterations << '\n';
    std::cout << "hooked_ns_per_call=" << static_cast<double>(hookedNs) / iterations << '\n';

    return EXIT_SUCCESS;
}


