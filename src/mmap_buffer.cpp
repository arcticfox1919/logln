// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "buffer.hpp"

#include <cstring>
#include <fstream>
#include <vector>

namespace logln {

// ============================================================================
// MmapBuffer Implementation
// Uses BufferView to wrap mmap memory
// ============================================================================

std::expected<std::unique_ptr<MmapBuffer>, MmapBuffer::Error>
MmapBuffer::create(const std::filesystem::path& path, std::size_t size) {
    if (size <= kHeaderSize) {
        return std::unexpected(Error::InvalidSize);
    }
    
    auto buffer = std::unique_ptr<MmapBuffer>(new MmapBuffer(path, size));
    
    if (!buffer->open_or_create()) {
        return std::unexpected(Error::MmapFailed);
    }
    
    return buffer;
}

MmapBuffer::MmapBuffer(std::filesystem::path path, std::size_t size)
    : path_(std::move(path))
    , total_size_(size) {
}

MmapBuffer::~MmapBuffer() {
    // Just unmap, no memset needed
    // If this is a clean shutdown, clear() should have been called already
    // If this is a crash, we want to preserve data for recovery
    if (is_mapped()) {
        mmap_.unmap();
    }
}

MmapBuffer::MmapBuffer(MmapBuffer&& other) noexcept
    : path_(std::move(other.path_))
    , total_size_(other.total_size_)
    , mmap_(std::move(other.mmap_))
    , view_(std::move(other.view_)) {
    other.total_size_ = 0;
}

MmapBuffer& MmapBuffer::operator=(MmapBuffer&& other) noexcept {
    if (this != &other) {
        if (is_mapped()) {
            mmap_.unmap();
        }
        path_ = std::move(other.path_);
        total_size_ = other.total_size_;
        mmap_ = std::move(other.mmap_);
        view_ = std::move(other.view_);
        other.total_size_ = 0;
    }
    return *this;
}

bool MmapBuffer::open_or_create() {
    std::error_code ec;
    
    // Ensure parent directory exists
    std::filesystem::create_directories(path_.parent_path(), ec);
    if (ec) return false;
    
    // Create file if not exists
    if (!std::filesystem::exists(path_)) {
        std::ofstream ofs(path_, std::ios::binary);
        if (!ofs) return false;
        
        // Write zeros to set file size
        std::vector<char> zeros(total_size_, 0);
        ofs.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
        if (!ofs) return false;
    } else {
        // Resize if needed
        auto file_size = std::filesystem::file_size(path_, ec);
        if (ec || file_size != total_size_) {
            std::filesystem::resize_file(path_, total_size_, ec);
            if (ec) return false;
        }
    }
    
    // Memory map the file
    mmap_ = mio::make_mmap_sink(path_.string(), ec);
    if (ec) return false;
    
    // Attach BufferView to mmap data area (after header)
    view_.attach(data_ptr(), data_capacity());
    
    // Sync size from mmap header (for crash recovery)
    sync_size_from_mmap();
    
    return true;
}

std::size_t MmapBuffer::write(const void* src, std::size_t len) noexcept {
    if (!is_mapped() || !src || len == 0) return 0;
    
    std::size_t written = view_.write(src, len);
    
    // Sync size to mmap header for crash safety
    sync_size_to_mmap();
    
    return written;
}

std::size_t MmapBuffer::write(std::span<const std::byte> src) noexcept {
    return write(src.data(), src.size());
}

void MmapBuffer::flush(AutoBuffer& out) {
    if (!is_mapped() || view_.empty()) return;
    
    // Copy data from mmap to AutoBuffer
    // Note: we do NOT clear here - caller should call clear() after
    // successfully writing to file (xlog pattern for crash safety)
    out.write(view_.data(), view_.size());
}

void MmapBuffer::clear() noexcept {
    if (!is_mapped()) return;
    
    view_.reset();
    sync_size_to_mmap();
}

std::span<const std::byte> MmapBuffer::recover() const noexcept {
    if (!is_mapped()) return {};
    
    // If view has data, it's from a previous crash
    if (view_.size() > 0 && view_.size() <= view_.capacity()) {
        return view_.as_span();
    }
    
    return {};
}

void MmapBuffer::sync_size_to_mmap() noexcept {
    if (auto* sz = size_ptr()) {
        *sz = view_.size();
    }
}

void MmapBuffer::sync_size_from_mmap() noexcept {
    if (const auto* sz = size_ptr()) {
        std::size_t stored_size = *sz;
        if (stored_size > 0 && stored_size <= data_capacity()) {
            view_.set_size(stored_size);
        }
    }
}

std::uint64_t* MmapBuffer::size_ptr() noexcept {
    if (!mmap_.is_open()) return nullptr;
    return reinterpret_cast<std::uint64_t*>(mmap_.data());
}

const std::uint64_t* MmapBuffer::size_ptr() const noexcept {
    if (!mmap_.is_open()) return nullptr;
    return reinterpret_cast<const std::uint64_t*>(mmap_.data());
}

std::byte* MmapBuffer::data_ptr() noexcept {
    if (!mmap_.is_open()) return nullptr;
    return reinterpret_cast<std::byte*>(mmap_.data() + kHeaderSize);
}

const std::byte* MmapBuffer::data_ptr() const noexcept {
    if (!mmap_.is_open()) return nullptr;
    return reinterpret_cast<const std::byte*>(mmap_.data() + kHeaderSize);
}

std::size_t MmapBuffer::data_capacity() const noexcept {
    return total_size_ > kHeaderSize ? total_size_ - kHeaderSize : 0;
}

} // namespace logln
