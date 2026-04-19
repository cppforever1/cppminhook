#pragma once

#include <cstddef>

#include "cppminhook/hook.h"

namespace cppminhook::relocator {

struct DecodedInstruction {
    std::size_t length = 0;
    bool supported = false;
};

[[nodiscard]] bool backend_available(DecoderBackend backend) noexcept;
[[nodiscard]] const char* backend_name(DecoderBackend backend) noexcept;
[[nodiscard]] DecodedInstruction decode_instruction(const std::byte* code, std::size_t remaining, DecoderBackend backend) noexcept;
[[nodiscard]] std::size_t calculate_patch_size(const std::byte* code, std::size_t maxSize,
                                               std::size_t minimumPatchSize, DecoderBackend backend) noexcept;
[[nodiscard]] bool relocate_instruction(const std::byte* sourceInstruction, std::byte* destinationInstruction,
                                        std::size_t instructionLength, const HookOptions& options,
                                        std::size_t* relocatedLength) noexcept;

} // namespace cppminhook::relocator