#pragma once

#include <string_view>

namespace cppminhook {

enum class Status {
    ok,
    already_initialized,
    not_initialized,
    already_created,
    not_created,
    already_enabled,
    already_disabled,
    invalid_argument,
    unsupported_target,
    address_not_executable,
    memory_allocation_failed,
    memory_protection_failed,
    module_not_found,
    function_not_found
};

[[nodiscard]] std::string_view to_string(Status status) noexcept;

} // namespace cppminhook