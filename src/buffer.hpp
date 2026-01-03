// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors
//
// Buffer design:
// - BufferView: lightweight non-owning wrapper for external memory
// - AutoBuffer: self-managed dynamic buffer with auto-growth
// - MmapBuffer: crash-safe buffer using mmap + BufferView

#pragma once

#include <mio/mmap.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <filesystem>
#include <memory>
#include <expected>
#include <vector>
#include <algorithm>

namespace logln {

// ============================================================================
// BufferView - Non-owning mutable view over contiguous memory
// Similar to std::span but with write position tracking.
// Does NOT own memory, just wraps a pointer with position/length tracking.
// Can wrap: stack memory, heap memory, mmap memory, etc.
// ============================================================================

class BufferView {
public:
    // Default constructor - empty view
    BufferView() noexcept = default;
    
    // Construct with external memory
    // @param data: pointer to external memory (not owned)
    // @param size: current used size
    // @param capacity: maximum capacity
    BufferView(void* data, std::size_t size, std::size_t capacity) noexcept
        : data_(static_cast<std::byte*>(data))
        , write_pos_(0)
        , size_(size)
        , capacity_(capacity) {}
    
    // Attach to external memory (transfer wrapper, not ownership)
    void attach(void* data, std::size_t capacity) noexcept {
        data_ = static_cast<std::byte*>(data);
        write_pos_ = 0;
        size_ = 0;
        capacity_ = capacity;
    }
    
    // Attach with existing size
    void attach(void* data, std::size_t size, std::size_t capacity) noexcept {
        data_ = static_cast<std::byte*>(data);
        write_pos_ = 0;
        size_ = size;
        capacity_ = capacity;
    }
    
    // Detach from memory (does NOT free)
    void detach() noexcept {
        data_ = nullptr;
        write_pos_ = 0;
        size_ = 0;
        capacity_ = 0;
    }
    
    // Reset size to zero (does not clear memory)
    void reset() noexcept {
        write_pos_ = 0;
        size_ = 0;
    }
    
    // Write data at current position
    // Returns actual bytes written (may be less if buffer full)
    std::size_t write(const void* src, std::size_t len) noexcept {
        if (!data_ || !src) return 0;
        
        std::size_t bytes_to_write = std::min(len, capacity_ - write_pos_);
        if (bytes_to_write > 0) {
            std::memcpy(data_ + write_pos_, src, bytes_to_write);
            write_pos_ += bytes_to_write;
            size_ = std::max(size_, write_pos_);
        }
        return bytes_to_write;
    }
    
    // Write data at specific position
    std::size_t write(const void* src, std::size_t len, std::size_t pos) noexcept {
        if (!data_ || !src || pos > capacity_) return 0;
        
        std::size_t bytes_to_write = std::min(len, capacity_ - pos);
        if (bytes_to_write > 0) {
            std::memcpy(data_ + pos, src, bytes_to_write);
            size_ = std::max(size_, pos + bytes_to_write);
        }
        return bytes_to_write;
    }
    
    // Write span
    std::size_t write(std::span<const std::byte> src) noexcept {
        return write(src.data(), src.size());
    }
    
    // Get pointer to start of buffer
    [[nodiscard]] std::byte* data() noexcept { return data_; }
    [[nodiscard]] const std::byte* data() const noexcept { return data_; }
    
    // Get pointer at current write position
    [[nodiscard]] std::byte* write_ptr() noexcept { return data_ ? data_ + write_pos_ : nullptr; }
    [[nodiscard]] const std::byte* write_ptr() const noexcept { return data_ ? data_ + write_pos_ : nullptr; }
    
    // Write position management
    [[nodiscard]] std::size_t write_pos() const noexcept { return write_pos_; }
    void seek(std::size_t pos) noexcept { write_pos_ = std::min(pos, capacity_); }
    
    // Size and capacity
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
    [[nodiscard]] std::size_t available() const noexcept { 
        return capacity_ > write_pos_ ? capacity_ - write_pos_ : 0; 
    }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] bool is_attached() const noexcept { return data_ != nullptr; }
    
    // Set size manually (for external writes like compression)
    void set_size(std::size_t new_size) noexcept { 
        size_ = std::min(new_size, capacity_); 
    }
    
    // Get data as span
    [[nodiscard]] std::span<const std::byte> as_span() const noexcept {
        return {data_, size_};
    }
    
private:
    std::byte* data_ = nullptr;
    std::size_t write_pos_ = 0;
    std::size_t size_ = 0;
    std::size_t capacity_ = 0;
};

// ============================================================================
// AutoBuffer - Self-managed dynamic buffer 
// OWNS memory, can grow automatically.
// Implemented as a thin wrapper over std::vector<std::byte>
// ============================================================================

class AutoBuffer {
public:
    // Default constructor
    AutoBuffer() noexcept = default;
    
    // Construct with initial capacity (pre-allocates memory, size remains 0)
    explicit AutoBuffer(std::size_t capacity) {
        buffer_.reserve(capacity);
    }
    
    // Destructor - vector handles memory automatically
    ~AutoBuffer() = default;
    
    // Move semantics - vector handles these automatically
    AutoBuffer(AutoBuffer&&) noexcept = default;
    AutoBuffer& operator=(AutoBuffer&&) noexcept = default;
    
    // Non-copyable
    AutoBuffer(const AutoBuffer&) = delete;
    AutoBuffer& operator=(const AutoBuffer&) = delete;
    
    // Write data at current position (auto-expands if needed)
    void write(const void* data, std::size_t len) {
        if (!data || len == 0) return;
        
        std::size_t new_end = pos_ + len;
        if (new_end > buffer_.capacity()) {
            buffer_.reserve(new_end * 2);  // 2x growth strategy
        }
        if (new_end > buffer_.size()) {
            buffer_.resize(new_end);
        }
        
        std::memcpy(buffer_.data() + pos_, data, len);
        pos_ = new_end;
    }
    
    // Write at specific position
    void write(std::size_t pos, const void* data, std::size_t len) {
        if (!data || len == 0) return;
        
        std::size_t new_end = pos + len;
        if (new_end > buffer_.capacity()) {
            buffer_.reserve(new_end * 2);
        }
        if (new_end > buffer_.size()) {
            buffer_.resize(new_end);
        }
        
        std::memcpy(buffer_.data() + pos, data, len);
    }
    
    // Write span
    void write(std::span<const std::byte> data) {
        write(data.data(), data.size());
    }
    
    // Reset position and size (keeps capacity)
    void reset() noexcept {
        pos_ = 0;
        buffer_.clear();  // size=0 but capacity preserved
    }
    
    // Clear and free memory
    void clear() noexcept {
        pos_ = 0;
        buffer_.clear();
        buffer_.shrink_to_fit();
    }
    
    // Reserve capacity without changing size
    void reserve(std::size_t capacity) {
        buffer_.reserve(capacity);
    }
    
    // Accessors
    [[nodiscard]] std::byte* ptr() noexcept { return buffer_.data(); }
    [[nodiscard]] const std::byte* ptr() const noexcept { return buffer_.data(); }
    [[nodiscard]] std::byte* pos_ptr() noexcept { 
        return buffer_.empty() ? nullptr : buffer_.data() + pos_; 
    }
    [[nodiscard]] const std::byte* pos_ptr() const noexcept { 
        return buffer_.empty() ? nullptr : buffer_.data() + pos_; 
    }
    
    [[nodiscard]] std::size_t pos() const noexcept { return pos_; }
    void seek(std::size_t pos) noexcept { pos_ = std::min(pos, buffer_.size()); }
    
    [[nodiscard]] std::size_t length() const noexcept { return buffer_.size(); }
    [[nodiscard]] std::size_t capacity() const noexcept { return buffer_.capacity(); }
    [[nodiscard]] std::size_t available() const noexcept { 
        return buffer_.capacity() > pos_ ? buffer_.capacity() - pos_ : 0; 
    }
    [[nodiscard]] bool empty() const noexcept { return buffer_.empty(); }
    
    // Get data as span
    [[nodiscard]] std::span<const std::byte> data() const noexcept {
        return {buffer_.data(), buffer_.size()};
    }
    
    // Direct access to underlying vector (for advanced use)
    [[nodiscard]] std::vector<std::byte>& underlying() noexcept { return buffer_; }
    [[nodiscard]] const std::vector<std::byte>& underlying() const noexcept { return buffer_; }
    
private:
    std::vector<std::byte> buffer_;
    std::size_t pos_ = 0;
};

// ============================================================================
// MmapBuffer - Memory-mapped buffer for crash recovery
// Uses BufferView to wrap mmap memory (does not own the mmap itself)
// ============================================================================

class MmapBuffer {
public:
    // Default buffer size: 150KB 
    static constexpr std::size_t kDefaultBufferSize = 150 * 1024;
    
    // Error types
    enum class Error {
        FileOpenFailed,
        MmapFailed,
        InvalidSize
    };
    
    // Create or open mmap buffer
    [[nodiscard]] static std::expected<std::unique_ptr<MmapBuffer>, Error>
    create(const std::filesystem::path& path, std::size_t size = kDefaultBufferSize);
    
    ~MmapBuffer();
    
    // Non-copyable, movable
    MmapBuffer(const MmapBuffer&) = delete;
    MmapBuffer& operator=(const MmapBuffer&) = delete;
    MmapBuffer(MmapBuffer&&) noexcept;
    MmapBuffer& operator=(MmapBuffer&&) noexcept;
    
    // Write data to mmap buffer
    // Returns actual bytes written
    std::size_t write(const void* src, std::size_t len) noexcept;
    std::size_t write(std::span<const std::byte> src) noexcept;
    
    // Flush to AutoBuffer (for async write to file)
    void flush(AutoBuffer& out);
    
    // Clear buffer (reset size to 0)
    void clear() noexcept;
    
    // Get underlying BufferView for direct access (e.g., compression)
    [[nodiscard]] BufferView& view() noexcept { return view_; }
    [[nodiscard]] const BufferView& view() const noexcept { return view_; }
    
    // Accessors
    [[nodiscard]] std::byte* data() noexcept { return view_.data(); }
    [[nodiscard]] const std::byte* data() const noexcept { return view_.data(); }
    [[nodiscard]] std::size_t size() const noexcept { return view_.size(); }
    [[nodiscard]] std::size_t capacity() const noexcept { return view_.capacity(); }
    [[nodiscard]] std::size_t available() const noexcept { return view_.available(); }
    [[nodiscard]] bool empty() const noexcept { return view_.empty(); }
    [[nodiscard]] bool is_mapped() const noexcept { return mmap_.is_open(); }
    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
    
    // Recover data from previous crash
    [[nodiscard]] std::span<const std::byte> recover() const noexcept;
    
private:
    MmapBuffer(std::filesystem::path path, std::size_t size);
    
    bool open_or_create();
    void sync_size_to_mmap() noexcept;
    void sync_size_from_mmap() noexcept;
    
    std::filesystem::path path_;
    std::size_t total_size_;      // Total mmap size including header
    mio::mmap_sink mmap_;
    BufferView view_;             // Wraps mmap data area (after header)
    
    // Simple header: just store current size (8 bytes)
    static constexpr std::size_t kHeaderSize = 8;
    
    std::uint64_t* size_ptr() noexcept;
    const std::uint64_t* size_ptr() const noexcept;
    std::byte* data_ptr() noexcept;
    const std::byte* data_ptr() const noexcept;
    std::size_t data_capacity() const noexcept;
};
} // namespace logln
