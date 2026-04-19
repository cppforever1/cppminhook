#pragma once

#include <array>
#include <cstddef>
#include <optional>

#include "cppminhook/status.h"
#include "cppminhook/trampoline_buffer.h"

namespace cppminhook {

enum class DecoderBackend {
    internal,
    capstone,
    zydis
};

struct HookOptions {
    DecoderBackend decoderBackend = DecoderBackend::internal;
    bool strictMode = true;
    bool failOnUnknownInstruction = true;
    bool allowShortBranchWidening = false;
    bool loadModuleIfNeeded = false;
    bool resolveForwardedExports = true;
};

class Hook {
public:
    Hook() = default;
    ~Hook();

    Hook(const Hook&) = delete;
    Hook& operator=(const Hook&) = delete;

    Hook(Hook&& other) noexcept;
    Hook& operator=(Hook&& other) noexcept;

    [[nodiscard]] Status create(void* target, void* detour, const HookOptions& options = HookOptions{}) noexcept;
    [[nodiscard]] Status enable() noexcept;
    [[nodiscard]] Status disable() noexcept;
    [[nodiscard]] Status remove() noexcept;
    void queue_enable() noexcept;
    void queue_disable() noexcept;
    void clear_queued_action() noexcept;
    [[nodiscard]] Status apply_queued() noexcept;

    [[nodiscard]] bool is_created() const noexcept;
    [[nodiscard]] bool is_enabled() const noexcept;
    [[nodiscard]] bool has_queued_action() const noexcept;
    [[nodiscard]] void* target() const noexcept;
    [[nodiscard]] void* detour() const noexcept;
    [[nodiscard]] void* trampoline() const noexcept;
    [[nodiscard]] std::size_t patch_size() const noexcept;
    [[nodiscard]] const HookOptions& options() const noexcept;

    template <typename FunctionPointer>
    [[nodiscard]] FunctionPointer original() const noexcept {
        return reinterpret_cast<FunctionPointer>(trampoline());
    }

private:
    enum class State {
        empty,
        created,
        enabled
    };

    [[nodiscard]] static std::size_t minimum_patch_size() noexcept;
    [[nodiscard]] static std::size_t jump_size() noexcept;
    [[nodiscard]] static bool is_executable_address(const void* address) noexcept;
    static void write_jump(std::byte* source, const void* destination) noexcept;

    [[nodiscard]] Status write_patch() noexcept;
    [[nodiscard]] Status restore_patch() noexcept;
    void move_from(Hook&& other) noexcept;
    void clear() noexcept;

    void* target_ = nullptr;
    void* detour_ = nullptr;
    std::size_t patchSize_ = 0;
    std::array<std::byte, 32> originalBytes_{};
    TrampolineBuffer trampolineBuffer_{};
    std::optional<bool> queuedEnable_{};
    HookOptions options_{};
    State state_ = State::empty;
};

} // namespace cppminhook

