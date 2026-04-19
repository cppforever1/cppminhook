#include "cppminhook/trampoline_buffer.h"

#include <utility>
#include <windows.h>

#include "cppminhook/diagnostics.h"

namespace cppminhook {

TrampolineBuffer::~TrampolineBuffer() {
    reset();
}

TrampolineBuffer::TrampolineBuffer(TrampolineBuffer&& other) noexcept {
    *this = std::move(other);
}

TrampolineBuffer& TrampolineBuffer::operator=(TrampolineBuffer&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    reset();
    buffer_ = other.buffer_;
    size_ = other.size_;
    other.buffer_ = nullptr;
    other.size_ = 0;
    return *this;
}

Status TrampolineBuffer::allocate(std::size_t size) noexcept {
    reset();

    if (size == 0) {
        report_diagnostic(Status::invalid_argument, "TrampolineBuffer::allocate.invalid_argument");
        return Status::invalid_argument;
    }

    buffer_ = ::VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (buffer_ == nullptr) {
        report_diagnostic(Status::memory_allocation_failed, "TrampolineBuffer::allocate.VirtualAlloc", ::GetLastError());
        return Status::memory_allocation_failed;
    }

    size_ = size;
    return Status::ok;
}

void TrampolineBuffer::reset() noexcept {
    if (buffer_ != nullptr) {
        ::VirtualFree(buffer_, 0, MEM_RELEASE);
    }

    buffer_ = nullptr;
    size_ = 0;
}

std::byte* TrampolineBuffer::data() noexcept {
    return static_cast<std::byte*>(buffer_);
}

const std::byte* TrampolineBuffer::data() const noexcept {
    return static_cast<const std::byte*>(buffer_);
}

std::size_t TrampolineBuffer::size() const noexcept {
    return size_;
}

bool TrampolineBuffer::empty() const noexcept {
    return buffer_ == nullptr;
}

} // namespace cppminhook

