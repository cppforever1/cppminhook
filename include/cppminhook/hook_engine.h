#pragma once

#include <mutex>
#include <string_view>
#include <memory>
#include <vector>

#include "cppminhook/hook.h"

namespace cppminhook {

class HookEngine {
public:
    HookEngine() = default;
    ~HookEngine();

    HookEngine(const HookEngine&) = delete;
    HookEngine& operator=(const HookEngine&) = delete;

    [[nodiscard]] Status initialize() noexcept;
    [[nodiscard]] Status uninitialize() noexcept;

    [[nodiscard]] Status create_hook(void* target, void* detour, Hook** createdHook = nullptr);
    [[nodiscard]] Status create_hook(void* target, void* detour, const HookOptions& options, Hook** createdHook = nullptr);
    [[nodiscard]] Status create_hook_api(std::wstring_view moduleName, std::string_view procName, void* detour,
                                         Hook** createdHook = nullptr, void** resolvedTarget = nullptr);
    [[nodiscard]] Status create_hook_api(std::wstring_view moduleName, std::string_view procName, void* detour,
                                         const HookOptions& options, Hook** createdHook = nullptr, void** resolvedTarget = nullptr);
    [[nodiscard]] Status resolve_api_target(std::wstring_view moduleName, std::string_view procName,
                                            void** resolvedTarget) const noexcept;
    [[nodiscard]] Status remove_hook(void* target) noexcept;
    [[nodiscard]] Status enable_all() noexcept;
    [[nodiscard]] Status disable_all() noexcept;
    [[nodiscard]] Status queue_enable(void* target) noexcept;
    [[nodiscard]] Status queue_disable(void* target) noexcept;
    [[nodiscard]] Status queue_enable_all() noexcept;
    [[nodiscard]] Status queue_disable_all() noexcept;
    [[nodiscard]] Status apply_queued() noexcept;

    [[nodiscard]] Status begin_transaction() noexcept;
    [[nodiscard]] Status commit_transaction() noexcept;
    [[nodiscard]] Status abort_transaction() noexcept;
    [[nodiscard]] bool transaction_active() const noexcept;

    [[nodiscard]] Hook* find_hook(void* target) noexcept;
    [[nodiscard]] const Hook* find_hook(void* target) const noexcept;
    [[nodiscard]] bool is_initialized() const noexcept;

private:
    [[nodiscard]] Hook* find_hook_unlocked(void* target) noexcept;
    [[nodiscard]] const Hook* find_hook_unlocked(void* target) const noexcept;

    mutable std::mutex mutex_{};
    bool initialized_ = false;
    bool transactionActive_ = false;
    std::vector<std::unique_ptr<Hook>> hooks_{};
};

} // namespace cppminhook

