#pragma once

#include <cstddef>
#include <windows.h>

#include "cppminhook/status.h"

namespace cppminhook {

class PageProtectionGuard {
public:
    PageProtectionGuard(void* address, std::size_t size, DWORD protection) noexcept;
    ~PageProtectionGuard();

    PageProtectionGuard(const PageProtectionGuard&) = delete;
    PageProtectionGuard& operator=(const PageProtectionGuard&) = delete;

    [[nodiscard]] Status status() const noexcept;

private:
    void* address_;
    std::size_t size_;
    DWORD previousProtection_;
    bool active_;
    Status status_;
};

} // namespace cppminhook

