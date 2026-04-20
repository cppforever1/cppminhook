#pragma once

#include <cstddef>
#include <string>

#include "cppminhook/status.h"

namespace cppminhook {

enum class DiagnosticCode {
    none,
    invalid_argument,
    backend_unavailable,
    unsupported_instruction,
    relocation_failed,
    patch_protection_failed,
    allocation_failed,
    module_resolution_failed,
    function_resolution_failed,
    internal_error
};

struct DiagnosticContext {
    Status status = Status::ok;
    unsigned long systemError = 0;
    const char* operation = nullptr;
    const void* targetAddress = nullptr;
    const void* detourAddress = nullptr;
    std::size_t patchSize = 0;
    const char* phase = nullptr;
    DiagnosticCode code = DiagnosticCode::none;
};

using LogCallback = void(*)(const DiagnosticContext& context);

void set_log_callback(LogCallback callback) noexcept;
[[nodiscard]] LogCallback get_log_callback() noexcept;

void report_diagnostic(const DiagnosticContext& context) noexcept;
void report_diagnostic(Status status, const char* operation, unsigned long systemError = 0) noexcept;
[[nodiscard]] DiagnosticContext last_diagnostic() noexcept;
[[nodiscard]] std::string default_log_file_path();
[[nodiscard]] std::string format_diagnostic(const DiagnosticContext& context);
[[nodiscard]] std::string format_last_diagnostic();
[[nodiscard]] std::string format_diagnostic_json(const DiagnosticContext& context);
[[nodiscard]] std::string format_last_diagnostic_json();
[[nodiscard]] const char* to_string(DiagnosticCode code) noexcept;
void clear_diagnostic() noexcept;

} // namespace cppminhook

