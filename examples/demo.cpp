#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <windows.h>

#include "cppminhook/hook_engine.h"
#include "cppminhook/status.h"

namespace {

using AddFunction = int(*)(int, int);

AddFunction g_originalAdd = nullptr;

int detour_add(int left, int right) {
    const auto originalResult = g_originalAdd != nullptr ? g_originalAdd(left, right) : 0;
    return originalResult + 100;
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

void print_status(const char* operation, cppminhook::Status status) {
    std::cout << operation << ": " << cppminhook::to_string(status) << '\n';
}

} // namespace

int main() {
    const auto bytes = sample_function_bytes();
    ExecutableBlock block(bytes.data(), bytes.size());
    if (block.data() == nullptr) {
        std::cerr << "VirtualAlloc failed for demo block\n";
        return EXIT_FAILURE;
    }

    auto function = reinterpret_cast<AddFunction>(block.data());
    std::cout << "Original result: " << function(3, 4) << '\n';

    cppminhook::HookEngine engine;
    auto status = engine.initialize();
    print_status("initialize", status);
    if (status != cppminhook::Status::ok) {
        return EXIT_FAILURE;
    }

    cppminhook::Hook* hook = nullptr;
    status = engine.create_hook(block.data(), reinterpret_cast<void*>(&detour_add), &hook);
    print_status("create_hook", status);
    if (status != cppminhook::Status::ok || hook == nullptr) {
        return EXIT_FAILURE;
    }

    g_originalAdd = hook->original<AddFunction>();
    status = hook->enable();
    print_status("enable", status);
    if (status != cppminhook::Status::ok) {
        return EXIT_FAILURE;
    }

    std::cout << "Hooked result: " << function(3, 4) << '\n';

    status = hook->disable();
    print_status("disable", status);
    if (status != cppminhook::Status::ok) {
        return EXIT_FAILURE;
    }

    std::cout << "Restored result: " << function(3, 4) << '\n';

    status = engine.uninitialize();
    print_status("uninitialize", status);
    return status == cppminhook::Status::ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

