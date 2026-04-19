#include <iostream>

#include <windows.h>

#include "cppminhook/hook_engine.h"

namespace {

using GetTickCountFn = unsigned long (WINAPI*)();
GetTickCountFn g_originalGetTickCount = nullptr;

unsigned long WINAPI detour_get_tick_count() {
    const unsigned long base = g_originalGetTickCount != nullptr ? g_originalGetTickCount() : 0UL;
    return base + 1UL;
}

} // namespace

int main() {
    cppminhook::HookEngine engine;
    if (engine.initialize() != cppminhook::Status::ok) {
        std::cerr << "Failed to initialize hook engine\n";
        return 1;
    }

    cppminhook::HookOptions options{};
    options.decoderBackend = cppminhook::DecoderBackend::internal;
    options.strictMode = true;
    options.failOnUnknownInstruction = true;
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

    if (createStatus != cppminhook::Status::ok || hook == nullptr || resolvedTarget == nullptr) {
        std::cerr << "create_hook_api failed\n";
        return 1;
    }

    g_originalGetTickCount = hook->original<GetTickCountFn>();

    if (engine.queue_enable_all() != cppminhook::Status::ok ||
        engine.apply_queued() != cppminhook::Status::ok) {
        std::cerr << "failed to enable hook\n";
        return 1;
    }

    const auto hookedTick = ::GetTickCount();

    if (engine.queue_disable_all() != cppminhook::Status::ok ||
        engine.apply_queued() != cppminhook::Status::ok) {
        std::cerr << "failed to disable hook\n";
        return 1;
    }

    std::cout << "Hooked GetTickCount value: " << hookedTick << '\n';

    if (engine.uninitialize() != cppminhook::Status::ok) {
        std::cerr << "uninitialize failed\n";
        return 1;
    }

    return 0;
}
