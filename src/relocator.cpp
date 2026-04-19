#include "cppminhook/relocator.h"

#include <bit>
#include <cstdint>
#include <cstring>
#include <limits>

#if defined(CPPMINHOOK_ENABLE_CAPSTONE)
#include <capstone/capstone.h>
#endif

#if defined(CPPMINHOOK_ENABLE_ZYDIS)
#include <Zydis/Zydis.h>
#endif

namespace cppminhook::relocator {

namespace {

[[nodiscard]] bool is_prefix_byte(unsigned char value) noexcept {
    switch (value) {
    case 0xF0:
    case 0xF2:
    case 0xF3:
    case 0x2E:
    case 0x36:
    case 0x3E:
    case 0x26:
    case 0x64:
    case 0x65:
    case 0x66:
    case 0x67:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] std::size_t modrm_length(const std::byte* code, std::size_t remaining, std::size_t offset) noexcept {
    if (offset >= remaining) {
        return 0;
    }

    const auto modrm = std::to_integer<unsigned char>(code[offset]);
    std::size_t length = 1;
    const auto mod = static_cast<unsigned char>((modrm >> 6) & 0x3U);
    const auto rm = static_cast<unsigned char>(modrm & 0x7U);

    if (rm == 4U && mod != 3U) {
        if (offset + length >= remaining) {
            return 0;
        }

        const auto sib = std::to_integer<unsigned char>(code[offset + length]);
        ++length;
        const auto base = static_cast<unsigned char>(sib & 0x7U);
        if (mod == 0U && base == 5U) {
            length += 4;
        }
    }

    if (mod == 0U && rm == 5U) {
        length += 4;
    } else if (mod == 1U) {
        length += 1;
    } else if (mod == 2U) {
        length += 4;
    }

    return offset + length <= remaining ? length : 0;
}

struct ModRmInfo {
    bool valid = false;
    std::size_t displacementOffset = 0;
    std::size_t displacementSize = 0;
};

[[nodiscard]] ModRmInfo parse_modrm(const std::byte* code, std::size_t remaining, std::size_t offset) noexcept {
    if (offset >= remaining) {
        return {};
    }

    ModRmInfo info{};
    const auto modrm = std::to_integer<unsigned char>(code[offset]);
    std::size_t length = 1;
    const auto mod = static_cast<unsigned char>((modrm >> 6) & 0x3U);
    const auto rm = static_cast<unsigned char>(modrm & 0x7U);

    if (rm == 4U && mod != 3U) {
        if (offset + length >= remaining) {
            return {};
        }

        const auto sib = std::to_integer<unsigned char>(code[offset + length]);
        ++length;
        const auto base = static_cast<unsigned char>(sib & 0x7U);
        if (mod == 0U && base == 5U) {
            info.displacementOffset = offset + length;
            info.displacementSize = 4;
            length += 4;
        }
    }

    if (mod == 0U && rm == 5U) {
        info.displacementOffset = offset + length;
        info.displacementSize = 4;
        length += 4;
    } else if (mod == 1U) {
        info.displacementOffset = offset + length;
        info.displacementSize = 1;
        length += 1;
    } else if (mod == 2U) {
        info.displacementOffset = offset + length;
        info.displacementSize = 4;
        length += 4;
    }

    if (offset + length > remaining) {
        return {};
    }

    info.valid = true;
    return info;
}

[[nodiscard]] bool is_modrm_opcode(unsigned char opcode) noexcept {
    switch (opcode) {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x18:
    case 0x19:
    case 0x1A:
    case 0x1B:
    case 0x20:
    case 0x21:
    case 0x22:
    case 0x23:
    case 0x28:
    case 0x29:
    case 0x2A:
    case 0x2B:
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x38:
    case 0x39:
    case 0x3A:
    case 0x3B:
    case 0x63:
    case 0x80:
    case 0x81:
    case 0x82:
    case 0x83:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
    case 0x88:
    case 0x89:
    case 0x8A:
    case 0x8B:
    case 0x8D:
    case 0x8F:
    case 0xC6:
    case 0xC7:
    case 0xFE:
    case 0xFF:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] bool fits_rel32(std::intptr_t value) noexcept {
    return value >= std::numeric_limits<std::int32_t>::min() && value <= std::numeric_limits<std::int32_t>::max();
}

[[nodiscard]] DecodedInstruction decode_instruction_internal(const std::byte* code, std::size_t remaining) noexcept {
    if (code == nullptr || remaining == 0) {
        return {};
    }

    std::size_t offset = 0;
    while (offset < remaining) {
        const auto value = std::to_integer<unsigned char>(code[offset]);
        if (is_prefix_byte(value)
#if defined(_M_X64) || defined(__x86_64__)
            || (value >= 0x40 && value <= 0x4F)
#endif
        ) {
            ++offset;
            continue;
        }
        break;
    }

    if (offset >= remaining) {
        return {};
    }

    const auto opcode = std::to_integer<unsigned char>(code[offset]);
    const auto prefixedLength = [&](std::size_t bodyLength) noexcept -> DecodedInstruction {
        return {offset + bodyLength, offset + bodyLength <= remaining};
    };

    if (opcode == 0x0F) {
        if (offset + 1 >= remaining) {
            return {};
        }

        const auto secondary = std::to_integer<unsigned char>(code[offset + 1]);
        if (secondary >= 0x80 && secondary <= 0x8F) {
            return prefixedLength(6);
        }

        if (secondary == 0x1F) {
            const auto extra = modrm_length(code, remaining, offset + 2);
            return {offset + 2 + extra, extra != 0};
        }

        return {};
    }

    if ((opcode >= 0x50 && opcode <= 0x5F) || opcode == 0x90 || opcode == 0xC3 || opcode == 0xCC) {
        return prefixedLength(1);
    }

    if (opcode == 0x6A || opcode == 0xA8 || opcode == 0xB0 || opcode == 0xB1 || opcode == 0xB2 || opcode == 0xB3 ||
        opcode == 0xB4 || opcode == 0xB5 || opcode == 0xB6 || opcode == 0xB7) {
        return prefixedLength(2);
    }

    if ((opcode >= 0xB8 && opcode <= 0xBF) || opcode == 0x68 || opcode == 0xA9 || opcode == 0xE8 || opcode == 0xE9) {
        return prefixedLength(5);
    }

    if (opcode == 0xEB || (opcode >= 0x70 && opcode <= 0x7F)) {
        return prefixedLength(2);
    }

    if (opcode == 0xC2) {
        return prefixedLength(3);
    }

    if (opcode == 0x81) {
        const auto extra = modrm_length(code, remaining, offset + 1);
        return {offset + 1 + extra + 4, extra != 0 && offset + 1 + extra + 4 <= remaining};
    }

    if (opcode == 0x80 || opcode == 0x82 || opcode == 0x83 || opcode == 0xC6) {
        const auto extra = modrm_length(code, remaining, offset + 1);
        return {offset + 1 + extra + 1, extra != 0 && offset + 1 + extra + 1 <= remaining};
    }

    if (opcode == 0x69 || opcode == 0xC7) {
        const auto extra = modrm_length(code, remaining, offset + 1);
        return {offset + 1 + extra + 4, extra != 0 && offset + 1 + extra + 4 <= remaining};
    }

    if (opcode == 0x6B) {
        const auto extra = modrm_length(code, remaining, offset + 1);
        return {offset + 1 + extra + 1, extra != 0 && offset + 1 + extra + 1 <= remaining};
    }

    if (is_modrm_opcode(opcode)) {
        const auto extra = modrm_length(code, remaining, offset + 1);
        return {offset + 1 + extra, extra != 0 && offset + 1 + extra <= remaining};
    }

    return {};
}

#if defined(CPPMINHOOK_ENABLE_CAPSTONE)
[[nodiscard]] DecodedInstruction decode_instruction_capstone(const std::byte* code, std::size_t remaining) noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    cs_mode mode = CS_MODE_64;
#else
    cs_mode mode = CS_MODE_32;
#endif

    csh handle = 0;
    if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
        return {};
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* instruction = nullptr;
    const size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t*>(code), remaining, 0, 1, &instruction);
    DecodedInstruction decoded{};
    if (count > 0 && instruction != nullptr && instruction[0].size > 0) {
        decoded.length = instruction[0].size;
        decoded.supported = instruction[0].size <= remaining;
    }

    if (instruction != nullptr) {
        cs_free(instruction, count);
    }
    cs_close(&handle);
    return decoded;
}
#endif

#if defined(CPPMINHOOK_ENABLE_ZYDIS)
[[nodiscard]] DecodedInstruction decode_instruction_zydis(const std::byte* code, std::size_t remaining) noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    ZydisMachineMode machineMode = ZYDIS_MACHINE_MODE_LONG_64;
    ZydisAddressWidth addressWidth = ZYDIS_ADDRESS_WIDTH_64;
#else
    ZydisMachineMode machineMode = ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
    ZydisAddressWidth addressWidth = ZYDIS_ADDRESS_WIDTH_32;
#endif

    ZydisDecoder decoder;
    if (ZYAN_FAILED(ZydisDecoderInit(&decoder, machineMode, addressWidth))) {
        return {};
    }

    ZydisDecodedInstruction instruction;
    if (ZYAN_FAILED(ZydisDecoderDecodeBuffer(&decoder, code, remaining, &instruction))) {
        return {};
    }

    return {instruction.length, instruction.length <= remaining};
}
#endif

} // namespace

bool backend_available(DecoderBackend backend) noexcept {
    switch (backend) {
    case DecoderBackend::internal:
        return true;
    case DecoderBackend::capstone:
#if defined(CPPMINHOOK_ENABLE_CAPSTONE)
        return true;
#else
        return false;
#endif
    case DecoderBackend::zydis:
#if defined(CPPMINHOOK_ENABLE_ZYDIS)
        return true;
#else
        return false;
#endif
    }

    return false;
}

const char* backend_name(DecoderBackend backend) noexcept {
    switch (backend) {
    case DecoderBackend::internal:
        return "internal";
    case DecoderBackend::capstone:
        return "capstone";
    case DecoderBackend::zydis:
        return "zydis";
    }

    return "unknown";
}

DecodedInstruction decode_instruction(const std::byte* code, std::size_t remaining, DecoderBackend backend) noexcept {
    switch (backend) {
    case DecoderBackend::internal:
        return decode_instruction_internal(code, remaining);
    case DecoderBackend::capstone:
#if defined(CPPMINHOOK_ENABLE_CAPSTONE)
        return decode_instruction_capstone(code, remaining);
#else
        return {};
#endif
    case DecoderBackend::zydis:
#if defined(CPPMINHOOK_ENABLE_ZYDIS)
        return decode_instruction_zydis(code, remaining);
#else
        return {};
#endif
    }

    return {};
}

std::size_t calculate_patch_size(const std::byte* code, std::size_t maxSize,
                                 std::size_t minimumPatchSize, DecoderBackend backend) noexcept {
    std::size_t offset = 0;
    while (offset < maxSize && offset < minimumPatchSize) {
        const auto decoded = decode_instruction(code + offset, maxSize - offset, backend);
        if (!decoded.supported || decoded.length == 0) {
            return 0;
        }

        offset += decoded.length;
    }

    return offset;
}

bool relocate_instruction(const std::byte* sourceInstruction, std::byte* destinationInstruction,
                         std::size_t instructionLength, const HookOptions& options,
                         std::size_t* relocatedLength) noexcept {
    if (instructionLength == 0 || relocatedLength == nullptr) {
        return false;
    }

    *relocatedLength = 0;
    std::memcpy(destinationInstruction, sourceInstruction, instructionLength);

    std::size_t prefixLength = 0;
    while (prefixLength < instructionLength) {
        const auto value = std::to_integer<unsigned char>(sourceInstruction[prefixLength]);
        if (is_prefix_byte(value)
#if defined(_M_X64) || defined(__x86_64__)
            || (value >= 0x40 && value <= 0x4F)
#endif
        ) {
            ++prefixLength;
            continue;
        }
        break;
    }

    if (prefixLength >= instructionLength) {
        return false;
    }

    const auto opcode = std::to_integer<unsigned char>(sourceInstruction[prefixLength]);

    if (opcode == 0xE8 || opcode == 0xE9) {
        if (prefixLength + 5 > instructionLength) {
            return false;
        }

        std::int32_t oldRelative = 0;
        std::memcpy(&oldRelative, sourceInstruction + prefixLength + 1, sizeof(oldRelative));
        const auto oldTarget = reinterpret_cast<std::intptr_t>(sourceInstruction + instructionLength) + oldRelative;
        const auto newRelative = oldTarget - reinterpret_cast<std::intptr_t>(destinationInstruction + instructionLength);
        if (!fits_rel32(newRelative)) {
            return false;
        }

        const auto adjusted = static_cast<std::int32_t>(newRelative);
        std::memcpy(destinationInstruction + prefixLength + 1, &adjusted, sizeof(adjusted));
        *relocatedLength = instructionLength;
        return true;
    }

    if (opcode == 0x0F && prefixLength + 1 < instructionLength) {
        const auto secondary = std::to_integer<unsigned char>(sourceInstruction[prefixLength + 1]);
        if (secondary >= 0x80 && secondary <= 0x8F) {
            if (prefixLength + 6 > instructionLength) {
                return false;
            }

            std::int32_t oldRelative = 0;
            std::memcpy(&oldRelative, sourceInstruction + prefixLength + 2, sizeof(oldRelative));
            const auto oldTarget = reinterpret_cast<std::intptr_t>(sourceInstruction + instructionLength) + oldRelative;
            const auto newRelative = oldTarget - reinterpret_cast<std::intptr_t>(destinationInstruction + instructionLength);
            if (!fits_rel32(newRelative)) {
                return false;
            }

            const auto adjusted = static_cast<std::int32_t>(newRelative);
            std::memcpy(destinationInstruction + prefixLength + 2, &adjusted, sizeof(adjusted));
            *relocatedLength = instructionLength;
            return true;
        }
    }

    if (opcode == 0xEB || (opcode >= 0x70 && opcode <= 0x7F)) {
        if (!options.allowShortBranchWidening || prefixLength + 2 > instructionLength) {
            return false;
        }

        const std::int8_t oldRelative = static_cast<std::int8_t>(
            std::to_integer<unsigned char>(sourceInstruction[prefixLength + 1]));
        const auto oldTarget = reinterpret_cast<std::intptr_t>(sourceInstruction + instructionLength) + oldRelative;

        if (opcode == 0xEB) {
            destinationInstruction[prefixLength] = std::byte{0xE9};
            const auto newRelative = oldTarget - reinterpret_cast<std::intptr_t>(destinationInstruction + prefixLength + 5);
            if (!fits_rel32(newRelative)) {
                return false;
            }

            const auto adjusted = static_cast<std::int32_t>(newRelative);
            std::memcpy(destinationInstruction + prefixLength + 1, &adjusted, sizeof(adjusted));
            *relocatedLength = prefixLength + 5;
            return true;
        }

        destinationInstruction[prefixLength] = std::byte{0x0F};
        destinationInstruction[prefixLength + 1] = static_cast<std::byte>(0x80U | (opcode & 0x0FU));
        const auto newRelative = oldTarget - reinterpret_cast<std::intptr_t>(destinationInstruction + prefixLength + 6);
        if (!fits_rel32(newRelative)) {
            return false;
        }

        const auto adjusted = static_cast<std::int32_t>(newRelative);
        std::memcpy(destinationInstruction + prefixLength + 2, &adjusted, sizeof(adjusted));
        *relocatedLength = prefixLength + 6;
        return true;
    }

#if defined(_M_X64) || defined(__x86_64__)
    if (is_modrm_opcode(opcode)) {
        const auto modrmInfo = parse_modrm(sourceInstruction, instructionLength, prefixLength + 1);
        if (!modrmInfo.valid) {
            return false;
        }

        if (modrmInfo.displacementSize == 4) {
            const auto modrm = std::to_integer<unsigned char>(sourceInstruction[prefixLength + 1]);
            const auto mod = static_cast<unsigned char>((modrm >> 6) & 0x3U);
            const auto rm = static_cast<unsigned char>(modrm & 0x7U);
            const bool isRipRelative = (mod == 0U && rm == 5U);
            if (isRipRelative) {
                std::int32_t oldDisplacement = 0;
                const auto localOffset = modrmInfo.displacementOffset;
                std::memcpy(&oldDisplacement, sourceInstruction + localOffset, sizeof(oldDisplacement));

                const auto oldTarget = reinterpret_cast<std::intptr_t>(sourceInstruction + instructionLength) + oldDisplacement;
                const auto newDisplacement = oldTarget - reinterpret_cast<std::intptr_t>(destinationInstruction + instructionLength);
                if (!fits_rel32(newDisplacement)) {
                    return false;
                }

                const auto adjusted = static_cast<std::int32_t>(newDisplacement);
                std::memcpy(destinationInstruction + localOffset, &adjusted, sizeof(adjusted));
            }
        }
    }
#endif

    *relocatedLength = instructionLength;
    return true;
}

} // namespace cppminhook::relocator
