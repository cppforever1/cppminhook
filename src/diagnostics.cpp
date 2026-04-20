#include "cppminhook/diagnostics.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <windows.h>

#include "cppminhook/status.h"

namespace cppminhook {

namespace {

void default_log_callback(const DiagnosticContext& context) noexcept;

[[nodiscard]] std::string make_default_log_path() {
    const auto now = std::chrono::system_clock::now();
    const auto nowTime = std::chrono::system_clock::to_time_t(now);
    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm localTime{};
    localtime_s(&localTime, &nowTime);

    std::ostringstream fileName;
    fileName << "cppminhook_";
    fileName << std::put_time(&localTime, "%Y%m%d_%H%M%S");
    fileName << '_' << std::setw(3) << std::setfill('0') << milliseconds.count();
    fileName << "_pid" << static_cast<unsigned long>(::GetCurrentProcessId()) << ".log";

    const std::filesystem::path filePath = std::filesystem::current_path() / fileName.str();
    return filePath.string();
}

thread_local DiagnosticContext g_lastDiagnostic{};
const std::string g_defaultLogPath = make_default_log_path();
std::ofstream g_defaultLogStream;
std::once_flag g_defaultLogInitFlag;
std::mutex g_defaultLogMutex;
std::atomic<LogCallback> g_logCallback{default_log_callback};

void ensure_default_log_open() {
    std::call_once(g_defaultLogInitFlag, []() {
        g_defaultLogStream.open(g_defaultLogPath, std::ios::out | std::ios::trunc);
    });
}

const bool g_defaultLogInitialized = []() {
    ensure_default_log_open();
    return true;
}();

void default_log_callback(const DiagnosticContext& context) noexcept {
    ensure_default_log_open();

    std::lock_guard<std::mutex> lock(g_defaultLogMutex);
    if (!g_defaultLogStream.is_open()) {
        return;
    }

    g_defaultLogStream << format_diagnostic_json(context) << '\n';
    g_defaultLogStream.flush();
}

[[nodiscard]] DiagnosticCode default_code_from_status(Status status) noexcept {
    switch (status) {
    case Status::invalid_argument:
        return DiagnosticCode::invalid_argument;
    case Status::unsupported_target:
        return DiagnosticCode::unsupported_instruction;
    case Status::memory_protection_failed:
        return DiagnosticCode::patch_protection_failed;
    case Status::memory_allocation_failed:
        return DiagnosticCode::allocation_failed;
    case Status::module_not_found:
        return DiagnosticCode::module_resolution_failed;
    case Status::function_not_found:
        return DiagnosticCode::function_resolution_failed;
    default:
        return DiagnosticCode::none;
    }
}

} // namespace

const char* to_string(DiagnosticCode code) noexcept {
    switch (code) {
    case DiagnosticCode::none:
        return "none";
    case DiagnosticCode::invalid_argument:
        return "invalid_argument";
    case DiagnosticCode::backend_unavailable:
        return "backend_unavailable";
    case DiagnosticCode::unsupported_instruction:
        return "unsupported_instruction";
    case DiagnosticCode::relocation_failed:
        return "relocation_failed";
    case DiagnosticCode::patch_protection_failed:
        return "patch_protection_failed";
    case DiagnosticCode::allocation_failed:
        return "allocation_failed";
    case DiagnosticCode::module_resolution_failed:
        return "module_resolution_failed";
    case DiagnosticCode::function_resolution_failed:
        return "function_resolution_failed";
    case DiagnosticCode::internal_error:
        return "internal_error";
    }

    return "unknown";
}

void set_log_callback(LogCallback callback) noexcept {
    g_logCallback.store(callback);
}

LogCallback get_log_callback() noexcept {
    return g_logCallback.load();
}

void report_diagnostic(const DiagnosticContext& context) noexcept {
    g_lastDiagnostic = context;
    if (g_lastDiagnostic.code == DiagnosticCode::none) {
        g_lastDiagnostic.code = default_code_from_status(g_lastDiagnostic.status);
    }

    LogCallback callback = g_logCallback.load();
    if (callback != nullptr && context.status != Status::ok) {
        callback(g_lastDiagnostic);
    }
}

void report_diagnostic(Status status, const char* operation, unsigned long systemError) noexcept {
    report_diagnostic(DiagnosticContext{status, systemError, operation, nullptr, nullptr, 0, nullptr,
                                        default_code_from_status(status)});
}

DiagnosticContext last_diagnostic() noexcept {
    return g_lastDiagnostic;
}

std::string default_log_file_path() {
    return g_defaultLogPath;
}

std::string format_diagnostic(const DiagnosticContext& context) {
    std::ostringstream stream;
    stream << "status=" << to_string(context.status);
    stream << ", code=" << to_string(context.code == DiagnosticCode::none ? default_code_from_status(context.status)
                                                                            : context.code);

    if (context.operation != nullptr) {
        stream << ", op=" << context.operation;
    }

    if (context.phase != nullptr) {
        stream << ", phase=" << context.phase;
    }

    if (context.targetAddress != nullptr) {
        stream << ", target=" << context.targetAddress;
    }

    if (context.detourAddress != nullptr) {
        stream << ", detour=" << context.detourAddress;
    }

    if (context.patchSize != 0) {
        stream << ", patchSize=" << context.patchSize;
    }

    if (context.systemError != 0) {
        stream << ", systemError=" << context.systemError;
    }

    return stream.str();
}

std::string format_last_diagnostic() {
    return format_diagnostic(last_diagnostic());
}

std::string format_diagnostic_json(const DiagnosticContext& context) {
    std::ostringstream stream;
    const DiagnosticCode code = context.code == DiagnosticCode::none ? default_code_from_status(context.status) : context.code;
    stream << "{";
    stream << "\"status\":\"" << to_string(context.status) << "\"";
    stream << ",\"code\":\"" << to_string(code) << "\"";

    if (context.operation != nullptr) {
        stream << ",\"operation\":\"" << context.operation << "\"";
    }

    if (context.phase != nullptr) {
        stream << ",\"phase\":\"" << context.phase << "\"";
    }

    if (context.targetAddress != nullptr) {
        stream << ",\"target\":\"" << context.targetAddress << "\"";
    }

    if (context.detourAddress != nullptr) {
        stream << ",\"detour\":\"" << context.detourAddress << "\"";
    }

    stream << ",\"patchSize\":" << context.patchSize;
    stream << ",\"systemError\":" << context.systemError;
    stream << "}";
    return stream.str();
}

std::string format_last_diagnostic_json() {
    return format_diagnostic_json(last_diagnostic());
}

void clear_diagnostic() noexcept {
    g_lastDiagnostic = {};
}

} // namespace cppminhook

