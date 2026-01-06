// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors
//
// LogBuffer - log buffer with header/tailer protocol
//
// Design Philosophy:
// - Crash-safe design (mmap + header + immediate processing)
// - Use modern C++ patterns (dependency injection, composition over inheritance)
// - Modular: compression/encryption are optional injected dependencies
//
// The mmap buffer maintains:
// | Header (73 bytes) | Processed Log Data... | Tailer (1 byte) |
//
// Crash recovery: On startup, check header magic and length to recover data.

#pragma once

#include "buffer.hpp"
#include "log_header.hpp"
#include "logln/types.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <span>
#include <string_view>

namespace logln {

// Forward declarations for optional dependencies
class ICompressor;
class IEncryptor;

// ============================================================================
// LogBuffer - crash-safe buffer with optional compression/encryption
//
// Usage:
//   // Without compression/encryption
//   LogBuffer buffer(mmap_ptr, mmap_size);
//
//   // With compression (using existing ZstdCompressor)
//   ZstdCompressor compressor;
//   LogBuffer buffer(mmap_ptr, mmap_size, &compressor);
//
//   // With compression and encryption
//   ZstdCompressor compressor;
//   TeaEncryptor encryptor(key);
//   LogBuffer buffer(mmap_ptr, mmap_size, &compressor, &encryptor);
// ============================================================================

class LogBuffer {
public:
    // Construct with external memory (mmap or heap)
    // Compressor and encryptor are optional - pass nullptr to disable
    // plain_text_mode: if true and no compressor/encryptor, skip protocol headers
    explicit LogBuffer(void* buffer, std::size_t size,
                       ICompressor* compressor = nullptr,
                       IEncryptor* encryptor = nullptr,
                       bool plain_text_mode = true);
    
    ~LogBuffer() = default;
    
    // Non-copyable, movable
    LogBuffer(const LogBuffer&) = delete;
    LogBuffer& operator=(const LogBuffer&) = delete;
    LogBuffer(LogBuffer&&) noexcept = default;
    LogBuffer& operator=(LogBuffer&&) noexcept = default;
    
    // ========== Write Operations ==========
    
    // Write log data (processes immediately if compressor/encryptor set)
    // Returns true on success, false if buffer full
    [[nodiscard]] bool write(const void* data, std::size_t len);
    [[nodiscard]] bool write(std::string_view data);
    
    // Write for sync mode - produces complete packet to output buffer
    // Does not modify internal buffer
    [[nodiscard]] bool write_sync(const void* data, std::size_t len, AutoBuffer& out);
    
    // ========== Flush Operations ==========
    
    // Flush buffer to output (adds tailer, copies data, clears buffer)
    // copy to AutoBuffer, then clear mmap
    void flush(AutoBuffer& out);
    
    // ========== State Query ==========
    
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] std::size_t length() const noexcept;      // Current used bytes
    [[nodiscard]] std::size_t capacity() const noexcept;    // Total capacity
    [[nodiscard]] std::size_t available() const noexcept;   // Remaining space
    
    // ========== Crash Recovery ==========
    
    // Try to recover data from previous crash
    // Returns true if valid data found, data copied to output
    [[nodiscard]] bool recover(AutoBuffer& out);
    
    // Reset buffer (clear and write fresh header)
    void reset();
    
    // Clear buffer completely
    void clear() noexcept;
    
    // ========== Configuration ==========
    
    [[nodiscard]] bool has_compressor() const noexcept { return compressor_ != nullptr; }
    [[nodiscard]] bool has_encryptor() const noexcept { return encryptor_ != nullptr; }
    
    // Returns true if using plain text mode (no protocol headers)
    [[nodiscard]] bool is_plain_text_mode() const noexcept { 
        return plain_text_mode_ && !compressor_ && !encryptor_; 
    }
    
    // Returns true if using binary mode (with protocol headers)
    [[nodiscard]] bool is_binary_mode() const noexcept { return !is_plain_text_mode(); }

private:
    // Process data through compression/encryption pipeline
    // Returns processed size, or 0 on failure
    std::size_t process_data(const void* src, std::size_t len,
                             void* dst, std::size_t dst_size);
    
    // Get magic byte based on current configuration
    [[nodiscard]] char get_magic() const noexcept;
    
    // Finalize buffer for flush (add tailer, update hour)
    void finalize();
    
    // Ensure buffer is initialized (header written)
    void ensure_initialized();
    
private:
    BufferView view_;                       // Wraps external memory
    ICompressor* compressor_ = nullptr;     // Optional, not owned
    IEncryptor* encryptor_ = nullptr;       // Optional, not owned
    LogHeader header_;
    bool initialized_ = false;              // Has header been written?
    bool plain_text_mode_ = true;           // Skip headers when no compression/encryption
    std::size_t remain_nocrypt_len_ = 0;    // Bytes from previous write not yet encrypted (streaming)
};

} // namespace logln
