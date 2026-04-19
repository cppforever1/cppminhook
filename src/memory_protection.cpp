#include "cppminhook/memory_protection.h"

#include <windows.h>

#include "cppminhook/diagnostics.h"

namespace cppminhook {

PageProtectionGuard::PageProtectionGuard(void* address, std::size_t size, DWORD protection) noexcept
    : address_(address),
      size_(size),
      previousProtection_(0),
      active_(false),
      status_(Status::invalid_argument) {
    if (address_ == nullptr || size_ == 0) {
        report_diagnostic(status_, "PageProtectionGuard::ctor.invalid_argument");
        return;
    }

    if (::VirtualProtect(address_, size_, protection, &previousProtection_) == 0) {
        status_ = Status::memory_protection_failed;
        report_diagnostic(status_, "PageProtectionGuard::ctor.VirtualProtect", ::GetLastError());
        return;
    }

    active_ = true;
    status_ = Status::ok;
}

PageProtectionGuard::~PageProtectionGuard() {
    if (!active_) {
        return;
    }

    DWORD restoredProtection = 0;
    ::VirtualProtect(address_, size_, previousProtection_, &restoredProtection);
}

Status PageProtectionGuard::status() const noexcept {
    return status_;
}

} // namespace cppminhook

