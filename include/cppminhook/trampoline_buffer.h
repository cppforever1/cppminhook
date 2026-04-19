#pragma once

#include <cstddef>

#include "cppminhook/status.h"

namespace cppminhook {

class TrampolineBuffer {
public:
    TrampolineBuffer() = default;
    ~TrampolineBuffer();

    TrampolineBuffer(const TrampolineBuffer&) = delete;
    TrampolineBuffer& operator=(const TrampolineBuffer&) = delete;

    TrampolineBuffer(TrampolineBuffer&& other) noexcept;
    TrampolineBuffer& operator=(TrampolineBuffer&& other) noexcept;

    [[nodiscard]] Status allocate(std::size_t size) noexcept;
    void reset() noexcept;

    [[nodiscard]] std::byte* data() noexcept;
    [[nodiscard]] const std::byte* data() const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;

private:
    void* buffer_ = nullptr;
    std::size_t size_ = 0;
};

} // namespace cppminhook

