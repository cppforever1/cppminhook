#include "cppminhook/hook_engine.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <windows.h>

#include "cppminhook/diagnostics.h"

namespace cppminhook {

namespace {

[[nodiscard]] std::wstring to_wstring_ascii(std::string_view value) {
    std::wstring converted;
    converted.reserve(value.size());
    for (const char character : value) {
        converted.push_back(static_cast<wchar_t>(static_cast<unsigned char>(character)));
    }
    return converted;
}

[[nodiscard]] std::string to_lower_ascii(std::string value) {
    for (char& character : value) {
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    }
    return value;
}

[[nodiscard]] bool has_dll_extension(std::string_view moduleName) {
    if (moduleName.size() < 4) {
        return false;
    }

    const std::string tail = to_lower_ascii(std::string(moduleName.substr(moduleName.size() - 4)));
    return tail == ".dll";
}

[[nodiscard]] HMODULE resolve_module_handle(std::wstring_view moduleName, bool loadIfNeeded) {
    std::wstring moduleNameBuffer(moduleName);
    HMODULE moduleHandle = ::GetModuleHandleW(moduleNameBuffer.c_str());
    if (moduleHandle == nullptr && loadIfNeeded) {
        moduleHandle = ::LoadLibraryW(moduleNameBuffer.c_str());
    }

    return moduleHandle;
}

[[nodiscard]] bool get_export_directory_range(HMODULE module, std::uintptr_t* begin, std::uintptr_t* end) {
    if (module == nullptr || begin == nullptr || end == nullptr) {
        return false;
    }

    const auto base = reinterpret_cast<const std::byte*>(module);
    const auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    const auto& directory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory.VirtualAddress == 0 || directory.Size == 0) {
        return false;
    }

    *begin = reinterpret_cast<std::uintptr_t>(base) + directory.VirtualAddress;
    *end = *begin + directory.Size;
    return true;
}

[[nodiscard]] bool is_forwarded_export(HMODULE module, FARPROC procedure) {
    if (module == nullptr || procedure == nullptr) {
        return false;
    }

    std::uintptr_t begin = 0;
    std::uintptr_t end = 0;
    if (!get_export_directory_range(module, &begin, &end)) {
        return false;
    }

    const auto value = reinterpret_cast<std::uintptr_t>(procedure);
    return value >= begin && value < end;
}

[[nodiscard]] Status resolve_procedure_with_forwarders(HMODULE initialModule,
                                                       std::string_view initialProc,
                                                       const HookOptions& options,
                                                       FARPROC* resolvedProcedure,
                                                       bool* usedForwarder) {
    if (initialModule == nullptr || initialProc.empty() || resolvedProcedure == nullptr) {
        return Status::invalid_argument;
    }

    *resolvedProcedure = nullptr;
    if (usedForwarder != nullptr) {
        *usedForwarder = false;
    }

    HMODULE module = initialModule;
    std::string procName(initialProc);

    for (int depth = 0; depth < 8; ++depth) {
        FARPROC procedure = ::GetProcAddress(module, procName.c_str());
        if (procedure == nullptr) {
            return Status::function_not_found;
        }

        if (!options.resolveForwardedExports || !is_forwarded_export(module, procedure)) {
            *resolvedProcedure = procedure;
            return Status::ok;
        }

        if (usedForwarder != nullptr) {
            *usedForwarder = true;
        }

        const char* forwarder = reinterpret_cast<const char*>(procedure);
        const char* separator = std::strchr(forwarder, '.');
        if (separator == nullptr) {
            return Status::function_not_found;
        }

        std::string nextModule(forwarder, static_cast<std::size_t>(separator - forwarder));
        std::string nextProc(separator + 1);

        if (!has_dll_extension(nextModule)) {
            nextModule += ".dll";
        }

        const std::wstring nextModuleWide = to_wstring_ascii(nextModule);
        module = resolve_module_handle(nextModuleWide, options.loadModuleIfNeeded);
        if (module == nullptr) {
            return Status::module_not_found;
        }

        if (!nextProc.empty() && nextProc.front() == '#') {
            const int ordinal = std::atoi(nextProc.c_str() + 1);
            if (ordinal <= 0) {
                return Status::function_not_found;
            }

            FARPROC ordinalProc = ::GetProcAddress(module, MAKEINTRESOURCEA(static_cast<WORD>(ordinal)));
            if (ordinalProc == nullptr) {
                return Status::function_not_found;
            }

            if (!options.resolveForwardedExports || !is_forwarded_export(module, ordinalProc)) {
                *resolvedProcedure = ordinalProc;
                return Status::ok;
            }

            // Continue the resolution loop if the ordinal points at another forwarder.
            procName = nextProc;
            continue;
        }

        procName = nextProc;
    }

    return Status::function_not_found;
}

} // namespace

HookEngine::~HookEngine() {
    static_cast<void>(uninitialize());
}

Status HookEngine::initialize() noexcept {
    std::scoped_lock lock(mutex_);
    if (initialized_) {
        report_diagnostic(Status::already_initialized, "HookEngine::initialize.already_initialized");
        return Status::already_initialized;
    }

    initialized_ = true;
    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::uninitialize() noexcept {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::uninitialize.not_initialized");
        return Status::not_initialized;
    }

    for (auto& hook : hooks_) {
        if (hook->is_enabled()) {
            static_cast<void>(hook->disable());
        }
    }

    for (auto& hook : hooks_) {
        static_cast<void>(hook->remove());
    }

    hooks_.clear();
    initialized_ = false;
    transactionActive_ = false;
    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::create_hook(void* target, void* detour, Hook** createdHook) {
    return create_hook(target, detour, HookOptions{}, createdHook);
}

Status HookEngine::create_hook(void* target, void* detour, const HookOptions& options, Hook** createdHook) {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::create_hook.not_initialized");
        return Status::not_initialized;
    }

    if (find_hook_unlocked(target) != nullptr) {
        report_diagnostic(Status::already_created, "HookEngine::create_hook.already_created");
        return Status::already_created;
    }

    auto hook = std::make_unique<Hook>();
    const Status status = hook->create(target, detour, options);
    if (status != Status::ok) {
        report_diagnostic(status, "HookEngine::create_hook.create_failed");
        return status;
    }

    if (createdHook != nullptr) {
        *createdHook = hook.get();
    }

    hooks_.push_back(std::move(hook));
    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::create_hook_api(std::wstring_view moduleName, std::string_view procName, void* detour,
                                   Hook** createdHook, void** resolvedTarget) {
    return create_hook_api(moduleName, procName, detour, HookOptions{}, createdHook, resolvedTarget);
}

Status HookEngine::create_hook_api(std::wstring_view moduleName, std::string_view procName, void* detour,
                                   const HookOptions& options, Hook** createdHook, void** resolvedTarget) {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::create_hook_api.not_initialized");
        return Status::not_initialized;
    }

    if (moduleName.empty() || procName.empty()) {
        report_diagnostic(Status::invalid_argument, "HookEngine::create_hook_api.invalid_argument");
        return Status::invalid_argument;
    }

    HMODULE moduleHandle = resolve_module_handle(moduleName, options.loadModuleIfNeeded);
    if (moduleHandle == nullptr) {
        report_diagnostic(DiagnosticContext{Status::module_not_found, ::GetLastError(), "HookEngine::create_hook_api.module", nullptr,
                                            detour, 0, "resolve", DiagnosticCode::module_resolution_failed});
        return Status::module_not_found;
    }

    FARPROC procedure = nullptr;
    bool usedForwarder = false;
    const Status resolveStatus = resolve_procedure_with_forwarders(moduleHandle, procName, options, &procedure, &usedForwarder);
    if (resolveStatus != Status::ok) {
        report_diagnostic(DiagnosticContext{resolveStatus, ::GetLastError(), "HookEngine::create_hook_api.procedure", nullptr,
                                            detour, 0, "resolve", DiagnosticCode::function_resolution_failed});
        return resolveStatus;
    }

    void* target = reinterpret_cast<void*>(procedure);
    if (resolvedTarget != nullptr) {
        *resolvedTarget = target;
    }

    if (find_hook_unlocked(target) != nullptr) {
        report_diagnostic(Status::already_created, "HookEngine::create_hook_api.already_created");
        return Status::already_created;
    }

    auto hook = std::make_unique<Hook>();
    const Status status = hook->create(target, detour, options);
    if (status != Status::ok) {
        report_diagnostic(status, usedForwarder ? "HookEngine::create_hook_api.create_failed.forwarded"
                                                : "HookEngine::create_hook_api.create_failed");
        return status;
    }

    if (createdHook != nullptr) {
        *createdHook = hook.get();
    }

    hooks_.push_back(std::move(hook));
    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::resolve_api_target(std::wstring_view moduleName, std::string_view procName,
                                      void** resolvedTarget) const noexcept {
    std::scoped_lock lock(mutex_);
    if (resolvedTarget == nullptr || moduleName.empty() || procName.empty()) {
        report_diagnostic(Status::invalid_argument, "HookEngine::resolve_api_target.invalid_argument");
        return Status::invalid_argument;
    }

    HMODULE moduleHandle = resolve_module_handle(moduleName, false);
    if (moduleHandle == nullptr) {
        report_diagnostic(Status::module_not_found, "HookEngine::resolve_api_target.GetModuleHandleW", ::GetLastError());
        return Status::module_not_found;
    }

    FARPROC procedure = nullptr;
    HookOptions resolutionOptions{};
    resolutionOptions.resolveForwardedExports = true;
    resolutionOptions.loadModuleIfNeeded = false;
    const Status status = resolve_procedure_with_forwarders(moduleHandle, procName, resolutionOptions, &procedure, nullptr);
    if (status != Status::ok) {
        report_diagnostic(status, "HookEngine::resolve_api_target.GetProcAddress", ::GetLastError());
        return status;
    }

    *resolvedTarget = reinterpret_cast<void*>(procedure);
    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::remove_hook(void* target) noexcept {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::remove_hook.not_initialized");
        return Status::not_initialized;
    }

    const auto iterator = std::find_if(hooks_.begin(), hooks_.end(), [target](const auto& hook) {
        return hook->target() == target;
    });

    if (iterator == hooks_.end()) {
        report_diagnostic(Status::not_created, "HookEngine::remove_hook.not_created");
        return Status::not_created;
    }

    const Status status = (*iterator)->remove();
    if (status != Status::ok) {
        report_diagnostic(status, "HookEngine::remove_hook.remove_failed");
        return status;
    }

    hooks_.erase(iterator);
    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::enable_all() noexcept {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::enable_all.not_initialized");
        return Status::not_initialized;
    }

    for (auto& hook : hooks_) {
        const Status status = hook->enable();
        if (status != Status::ok && status != Status::already_enabled) {
            report_diagnostic(status, "HookEngine::enable_all.enable_failed");
            return status;
        }
    }

    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::disable_all() noexcept {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::disable_all.not_initialized");
        return Status::not_initialized;
    }

    for (auto& hook : hooks_) {
        const Status status = hook->disable();
        if (status != Status::ok && status != Status::already_disabled && status != Status::not_created) {
            report_diagnostic(status, "HookEngine::disable_all.disable_failed");
            return status;
        }
    }

    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::queue_enable(void* target) noexcept {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::queue_enable.not_initialized");
        return Status::not_initialized;
    }

    Hook* hook = find_hook_unlocked(target);
    if (hook == nullptr) {
        report_diagnostic(Status::not_created, "HookEngine::queue_enable.not_created");
        return Status::not_created;
    }

    hook->queue_enable();
    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::queue_disable(void* target) noexcept {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::queue_disable.not_initialized");
        return Status::not_initialized;
    }

    Hook* hook = find_hook_unlocked(target);
    if (hook == nullptr) {
        report_diagnostic(Status::not_created, "HookEngine::queue_disable.not_created");
        return Status::not_created;
    }

    hook->queue_disable();
    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::queue_enable_all() noexcept {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::queue_enable_all.not_initialized");
        return Status::not_initialized;
    }

    for (auto& hook : hooks_) {
        hook->queue_enable();
    }

    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::queue_disable_all() noexcept {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::queue_disable_all.not_initialized");
        return Status::not_initialized;
    }

    for (auto& hook : hooks_) {
        hook->queue_disable();
    }

    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::apply_queued() noexcept {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::apply_queued.not_initialized");
        return Status::not_initialized;
    }

    std::vector<Hook*> affectedHooks;
    std::vector<bool> previousEnabled;
    affectedHooks.reserve(hooks_.size());
    previousEnabled.reserve(hooks_.size());

    for (auto& hook : hooks_) {
        if (hook->has_queued_action()) {
            affectedHooks.push_back(hook.get());
            previousEnabled.push_back(hook->is_enabled());
        }
    }

    std::size_t appliedCount = 0;
    for (; appliedCount < affectedHooks.size(); ++appliedCount) {
        const Status status = affectedHooks[appliedCount]->apply_queued();
        if (status != Status::ok && status != Status::already_enabled && status != Status::already_disabled) {
            for (std::size_t rollbackIndex = 0; rollbackIndex < appliedCount; ++rollbackIndex) {
                if (previousEnabled[rollbackIndex]) {
                    static_cast<void>(affectedHooks[rollbackIndex]->enable());
                } else {
                    static_cast<void>(affectedHooks[rollbackIndex]->disable());
                }
            }

            report_diagnostic(status, "HookEngine::apply_queued.apply_failed");
            return status;
        }
    }

    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::begin_transaction() noexcept {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::begin_transaction.not_initialized");
        return Status::not_initialized;
    }

    if (transactionActive_) {
        report_diagnostic(Status::already_enabled, "HookEngine::begin_transaction.already_active");
        return Status::already_enabled;
    }

    transactionActive_ = true;
    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::commit_transaction() noexcept {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::commit_transaction.not_initialized");
        return Status::not_initialized;
    }

    if (!transactionActive_) {
        report_diagnostic(Status::already_disabled, "HookEngine::commit_transaction.not_active");
        return Status::already_disabled;
    }

    transactionActive_ = false;

    std::vector<Hook*> affectedHooks;
    std::vector<bool> previousEnabled;
    affectedHooks.reserve(hooks_.size());
    previousEnabled.reserve(hooks_.size());

    for (auto& hook : hooks_) {
        if (hook->has_queued_action()) {
            affectedHooks.push_back(hook.get());
            previousEnabled.push_back(hook->is_enabled());
        }
    }

    std::size_t appliedCount = 0;
    for (; appliedCount < affectedHooks.size(); ++appliedCount) {
        const Status status = affectedHooks[appliedCount]->apply_queued();
        if (status != Status::ok && status != Status::already_enabled && status != Status::already_disabled) {
            for (std::size_t rollbackIndex = 0; rollbackIndex < appliedCount; ++rollbackIndex) {
                if (previousEnabled[rollbackIndex]) {
                    static_cast<void>(affectedHooks[rollbackIndex]->enable());
                } else {
                    static_cast<void>(affectedHooks[rollbackIndex]->disable());
                }
            }

            report_diagnostic(status, "HookEngine::commit_transaction.apply_failed");
            return status;
        }
    }

    clear_diagnostic();
    return Status::ok;
}

Status HookEngine::abort_transaction() noexcept {
    std::scoped_lock lock(mutex_);
    if (!initialized_) {
        report_diagnostic(Status::not_initialized, "HookEngine::abort_transaction.not_initialized");
        return Status::not_initialized;
    }

    if (!transactionActive_) {
        report_diagnostic(Status::already_disabled, "HookEngine::abort_transaction.not_active");
        return Status::already_disabled;
    }

    for (auto& hook : hooks_) {
        hook->clear_queued_action();
    }

    transactionActive_ = false;
    clear_diagnostic();
    return Status::ok;
}

bool HookEngine::transaction_active() const noexcept {
    std::scoped_lock lock(mutex_);
    return transactionActive_;
}

Hook* HookEngine::find_hook(void* target) noexcept {
    std::scoped_lock lock(mutex_);
    return find_hook_unlocked(target);
}

const Hook* HookEngine::find_hook(void* target) const noexcept {
    std::scoped_lock lock(mutex_);
    return find_hook_unlocked(target);
}

Hook* HookEngine::find_hook_unlocked(void* target) noexcept {
    const auto iterator = std::find_if(hooks_.begin(), hooks_.end(), [target](const auto& hook) {
        return hook->target() == target;
    });

    return iterator == hooks_.end() ? nullptr : iterator->get();
}

const Hook* HookEngine::find_hook_unlocked(void* target) const noexcept {
    const auto iterator = std::find_if(hooks_.begin(), hooks_.end(), [target](const auto& hook) {
        return hook->target() == target;
    });

    return iterator == hooks_.end() ? nullptr : iterator->get();
}

bool HookEngine::is_initialized() const noexcept {
    std::scoped_lock lock(mutex_);
    return initialized_;
}

} // namespace cppminhook
