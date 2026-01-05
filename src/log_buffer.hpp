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
// LogMagicNum - Magic numbers for log format identification
// ============================================================================

struct LogMagicNum {
    // Format: 0x06 + (compressed ? 1 : 0) + (encrypted ? 2 : 0)
    // Simplified: no sync/async distinction (not needed for decoding)
    
    static constexpr char kMagicNoFeature      = '\x06';
    static constexpr char kMagicCompressed     = '\x07';
    static constexpr char kMagicEncrypted      = '\x08';
    static constexpr char kMagicCompEncrypted  = '\x09';
    
    static constexpr char kMagicEnd = '\x00';
    
    [[nodiscard]] static constexpr bool is_valid_start(char magic) noexcept {
        return magic >= '\x06' && magic <= '\x09';
    }
    
    [[nodiscard]] static constexpr bool is_compressed(char magic) noexcept {
        return ((magic - kMagicNoFeature) & 0x01) != 0;
    }
    
    [[nodiscard]] static constexpr bool is_encrypted(char magic) noexcept {
        return ((magic - kMagicNoFeature) & 0x02) != 0;
    }
    
    [[nodiscard]] static constexpr char make_magic(bool compressed, 
                                                    bool encrypted) noexcept {
        char base = '\x06';
        if (compressed) base += 1;
        if (encrypted) base += 2;
        return base;
    }
};

// ============================================================================
// LogHeader - Buffer header for crash recovery 
//
// Header format (73 bytes):
// | magic (1) | seq (2) | begin_hour (1) | end_hour (1) | length (4) | client_pubkey (64) |
//
// Tailer format (1 byte):
// | magic_end (1) |
//
// Note: client_pubkey is used for ECDH key exchange when encryption is enabled
// ============================================================================

class LogHeader {
public:
    static constexpr std::size_t kHeaderSize = 73;  // 9 + 64 (client pubkey)
    static constexpr std::size_t kTailerSize = 1;
    static constexpr std::size_t kClientPubKeyOffset = 9;  // After magic, seq, hours, length
    static constexpr std::size_t kClientPubKeySize = 64;
    
    LogHeader() = default;
    
    // Write header to buffer
    void write_header(std::byte* buffer, 
                      bool compressed, bool encrypted) noexcept;
    
    // Write tailer to buffer  
    static void write_tailer(std::byte* buffer) noexcept;
    
    // Set client public key in header (for ECDH encryption)
    static void set_client_pubkey(std::byte* header, 
                                   std::span<const std::byte> pubkey) noexcept;
    
    // Get client public key from header
    [[nodiscard]] static std::span<const std::byte> get_client_pubkey(
        const std::byte* header) noexcept;
    
    // Update data length in header (accumulative)
    static void add_length(std::byte* header, std::uint32_t add_len) noexcept;
    
    // Set data length in header (absolute)
    static void set_length(std::byte* header, std::uint32_t len) noexcept;
    
    // Get current data length from header
    [[nodiscard]] static std::uint32_t get_length(const std::byte* header) noexcept;
    
    // Update end hour timestamp
    static void update_end_hour(std::byte* header) noexcept;
    
    // Validate header and get length (for crash recovery)
    // Returns true if valid, sets out_length to data length
    [[nodiscard]] static bool validate_and_get_length(
        const std::byte* header, 
        std::size_t buffer_size,
        std::uint32_t& out_length) noexcept;

private:
    std::uint16_t seq_ = 0;
    
    std::uint16_t next_seq() noexcept;
};

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
