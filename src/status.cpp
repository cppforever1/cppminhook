#include "cppminhook/status.h"

namespace cppminhook {

std::string_view to_string(Status status) noexcept {
    switch (status) {
    case Status::ok:
        return "ok";
    case Status::already_initialized:
        return "already_initialized";
    case Status::not_initialized:
        return "not_initialized";
    case Status::already_created:
        return "already_created";
    case Status::not_created:
        return "not_created";
    case Status::already_enabled:
        return "already_enabled";
    case Status::already_disabled:
        return "already_disabled";
    case Status::invalid_argument:
        return "invalid_argument";
    case Status::unsupported_target:
        return "unsupported_target";
    case Status::address_not_executable:
        return "address_not_executable";
    case Status::memory_allocation_failed:
        return "memory_allocation_failed";
    case Status::memory_protection_failed:
        return "memory_protection_failed";
    case Status::module_not_found:
        return "module_not_found";
    case Status::function_not_found:
        return "function_not_found";
    }

    return "unknown";
}

} // namespace cppminhook

