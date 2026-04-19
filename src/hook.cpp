#include "cppminhook/hook.h"

#include <cstdint>
#include <cstring>
#include <mutex>
#include <utility>

#include <windows.h>

#include "cppminhook/diagnostics.h"
#include "cppminhook/memory_protection.h"
#include "cppminhook/relocator.h"

namespace cppminhook {

namespace {

[[nodiscard]] bool is_executable_protection(DWORD protection) noexcept {
    constexpr DWORD executableMask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (protection & executableMask) != 0;
}

std::mutex g_patchWriteMutex;

} // namespace

Hook::~Hook() {
    static_cast<void>(remove());
}

Hook::Hook(Hook&& other) noexcept {
    move_from(std::move(other));
}

Hook& Hook::operator=(Hook&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    static_cast<void>(remove());
    move_from(std::move(other));
    return *this;
}

Status Hook::create(void* target, void* detour, const HookOptions& options) noexcept {
    options_ = options;

    if (!relocator::backend_available(options_.decoderBackend)) {
        report_diagnostic(DiagnosticContext{Status::unsupported_target, 0, "Hook::create.decoder_backend_unavailable",
                                            target, detour, 0, relocator::backend_name(options_.decoderBackend),
                                            DiagnosticCode::backend_unavailable});
        return Status::unsupported_target;
    }

    if (state_ != State::empty) {
        report_diagnostic(DiagnosticContext{Status::already_created, 0, "Hook::create.already_created", target, detour, 0, "create"});
        return Status::already_created;
    }

    if (target == nullptr || detour == nullptr) {
        report_diagnostic(DiagnosticContext{Status::invalid_argument, 0, "Hook::create.invalid_argument", target, detour, 0, "create"});
        return Status::invalid_argument;
    }

    if (!is_executable_address(target) || !is_executable_address(detour)) {
        report_diagnostic(DiagnosticContext{Status::address_not_executable, 0, "Hook::create.address_not_executable", target, detour, 0, "create"});
        return Status::address_not_executable;
    }

    target_ = target;
    detour_ = detour;
    patchSize_ = relocator::calculate_patch_size(
        static_cast<const std::byte*>(target_),
        originalBytes_.size(),
        minimum_patch_size(),
        options_.decoderBackend);
    if (patchSize_ < minimum_patch_size()) {
        clear();
        report_diagnostic(DiagnosticContext{Status::unsupported_target, 0, "Hook::create.patch_size_too_small", target_, detour_, patchSize_, "create"});
        return Status::unsupported_target;
    }

    std::memcpy(originalBytes_.data(), target_, patchSize_);

    const std::size_t trampolineSize = patchSize_ + jump_size() + (patchSize_ * 6);
    const Status allocationStatus = trampolineBuffer_.allocate(trampolineSize);
    if (allocationStatus != Status::ok) {
        clear();
        report_diagnostic(DiagnosticContext{allocationStatus, 0, "Hook::create.trampoline_allocate_failed", target_, detour_, patchSize_, "create"});
        return allocationStatus;
    }

    std::size_t sourceOffset = 0;
    std::size_t trampolineOffset = 0;
    while (sourceOffset < patchSize_) {
        const auto decoded = relocator::decode_instruction(
            static_cast<const std::byte*>(target_) + sourceOffset,
            patchSize_ - sourceOffset,
            options_.decoderBackend);
        if (!decoded.supported || decoded.length == 0) {
            trampolineBuffer_.reset();
            clear();
            const auto failureStatus = options_.failOnUnknownInstruction ? Status::unsupported_target : Status::invalid_argument;
            report_diagnostic(DiagnosticContext{failureStatus, 0, "Hook::create.decode_failed", target_, detour_, patchSize_,
                                                "create", DiagnosticCode::unsupported_instruction});
            return failureStatus;
        }

        std::size_t relocatedLength = 0;
        if (!relocator::relocate_instruction(static_cast<const std::byte*>(target_) + sourceOffset,
                                             trampolineBuffer_.data() + trampolineOffset,
                                             decoded.length,
                                             options_,
                                             &relocatedLength)) {
            if (!options_.strictMode) {
                std::memcpy(trampolineBuffer_.data() + trampolineOffset,
                            static_cast<const std::byte*>(target_) + sourceOffset,
                            decoded.length);
                relocatedLength = decoded.length;
                sourceOffset += decoded.length;
                trampolineOffset += relocatedLength;
                continue;
            }

            trampolineBuffer_.reset();
            clear();
            report_diagnostic(DiagnosticContext{Status::unsupported_target, 0, "Hook::create.relocation_failed", target_, detour_,
                                                patchSize_, "create", DiagnosticCode::relocation_failed});
            return Status::unsupported_target;
        }

        if (trampolineOffset + relocatedLength + jump_size() > trampolineBuffer_.size()) {
            trampolineBuffer_.reset();
            clear();
            report_diagnostic(DiagnosticContext{Status::memory_allocation_failed, 0, "Hook::create.trampoline_overflow", target_,
                                                detour_, patchSize_, "create", DiagnosticCode::allocation_failed});
            return Status::memory_allocation_failed;
        }

        sourceOffset += decoded.length;
        trampolineOffset += relocatedLength;
    }

    write_jump(trampolineBuffer_.data() + trampolineOffset, static_cast<std::byte*>(target_) + patchSize_);
    state_ = State::created;
    clear_diagnostic();
    return Status::ok;
}

void Hook::queue_enable() noexcept {
    queuedEnable_ = true;
}

void Hook::queue_disable() noexcept {
    queuedEnable_ = false;
}

void Hook::clear_queued_action() noexcept {
    queuedEnable_.reset();
}

Status Hook::apply_queued() noexcept {
    if (!queuedEnable_.has_value()) {
        return Status::ok;
    }

    const bool shouldEnable = *queuedEnable_;
    queuedEnable_.reset();
    return shouldEnable ? enable() : disable();
}

Status Hook::enable() noexcept {
    if (state_ == State::empty) {
        return Status::not_created;
    }

    if (state_ == State::enabled) {
        return Status::already_enabled;
    }

    return write_patch();
}

Status Hook::disable() noexcept {
    if (state_ == State::empty) {
        return Status::not_created;
    }

    if (state_ == State::created) {
        return Status::already_disabled;
    }

    return restore_patch();
}

Status Hook::remove() noexcept {
    if (state_ == State::empty) {
        return Status::not_created;
    }

    if (state_ == State::enabled) {
        const Status disableStatus = disable();
        if (disableStatus != Status::ok) {
            return disableStatus;
        }
    }

    trampolineBuffer_.reset();
    clear();
    return Status::ok;
}

bool Hook::is_created() const noexcept {
    return state_ != State::empty;
}

bool Hook::is_enabled() const noexcept {
    return state_ == State::enabled;
}

bool Hook::has_queued_action() const noexcept {
    return queuedEnable_.has_value();
}

void* Hook::target() const noexcept {
    return target_;
}

void* Hook::detour() const noexcept {
    return detour_;
}

void* Hook::trampoline() const noexcept {
    return const_cast<std::byte*>(trampolineBuffer_.data());
}

std::size_t Hook::patch_size() const noexcept {
    return patchSize_;
}

const HookOptions& Hook::options() const noexcept {
    return options_;
}

std::size_t Hook::minimum_patch_size() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    return 14;
#else
    return 5;
#endif
}

std::size_t Hook::jump_size() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    return 14;
#else
    return 5;
#endif
}

bool Hook::is_executable_address(const void* address) noexcept {
    MEMORY_BASIC_INFORMATION info{};
    if (::VirtualQuery(address, &info, sizeof(info)) == 0) {
        return false;
    }

    if (info.State != MEM_COMMIT) {
        return false;
    }

    if ((info.Protect & PAGE_GUARD) != 0 || (info.Protect & PAGE_NOACCESS) != 0) {
        return false;
    }

    return is_executable_protection(info.Protect);
}

void Hook::write_jump(std::byte* source, const void* destination) noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    source[0] = std::byte{0xFF};
    source[1] = std::byte{0x25};
    source[2] = std::byte{0x00};
    source[3] = std::byte{0x00};
    source[4] = std::byte{0x00};
    source[5] = std::byte{0x00};

    const auto address = reinterpret_cast<unsigned long long>(destination);
    std::memcpy(source + 6, &address, sizeof(address));
#else
    source[0] = std::byte{0xE9};

    const auto sourceAddress = reinterpret_cast<std::intptr_t>(source);
    const auto destinationAddress = reinterpret_cast<std::intptr_t>(destination);
    const auto relativeAddress = destinationAddress - (sourceAddress + static_cast<std::intptr_t>(jump_size()));
    const auto relativeJump = static_cast<std::int32_t>(relativeAddress);
    std::memcpy(source + 1, &relativeJump, sizeof(relativeJump));
#endif
}

Status Hook::write_patch() noexcept {
    std::scoped_lock patchLock(g_patchWriteMutex);
    PageProtectionGuard guard(target_, patchSize_, PAGE_EXECUTE_READWRITE);
    if (guard.status() != Status::ok) {
        report_diagnostic(DiagnosticContext{guard.status(), 0, "Hook::write_patch.protect_failed", target_, detour_, patchSize_,
                                            "enable", DiagnosticCode::patch_protection_failed});
        return guard.status();
    }

    std::memset(target_, 0x90, patchSize_);
    write_jump(static_cast<std::byte*>(target_), detour_);
    ::FlushInstructionCache(::GetCurrentProcess(), target_, patchSize_);
    state_ = State::enabled;
    clear_diagnostic();
    return Status::ok;
}

Status Hook::restore_patch() noexcept {
    std::scoped_lock patchLock(g_patchWriteMutex);
    PageProtectionGuard guard(target_, patchSize_, PAGE_EXECUTE_READWRITE);
    if (guard.status() != Status::ok) {
        report_diagnostic(DiagnosticContext{guard.status(), 0, "Hook::restore_patch.protect_failed", target_, detour_, patchSize_,
                                            "disable", DiagnosticCode::patch_protection_failed});
        return guard.status();
    }

    std::memcpy(target_, originalBytes_.data(), patchSize_);
    ::FlushInstructionCache(::GetCurrentProcess(), target_, patchSize_);
    state_ = State::created;
    clear_diagnostic();
    return Status::ok;
}

void Hook::move_from(Hook&& other) noexcept {
    target_ = other.target_;
    detour_ = other.detour_;
    patchSize_ = other.patchSize_;
    originalBytes_ = other.originalBytes_;
    trampolineBuffer_ = std::move(other.trampolineBuffer_);
    state_ = other.state_;
    queuedEnable_ = other.queuedEnable_;
    options_ = other.options_;
    other.clear();
}

void Hook::clear() noexcept {
    target_ = nullptr;
    detour_ = nullptr;
    patchSize_ = 0;
    originalBytes_.fill(std::byte{0});
    queuedEnable_.reset();
    options_ = HookOptions{};
    state_ = State::empty;
}

} // namespace cppminhook
