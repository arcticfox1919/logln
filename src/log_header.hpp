// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors
//
// Log Header Definitions
//
// This header defines the binary format for log buffer headers:
// - Magic numbers for format identification
// - Header/Tailer structure for crash recovery
//
// Buffer format:
// | Header (73 bytes) | Processed Log Data... | Tailer (1 byte) |
//
// Header format (73 bytes):
// | magic (1) | seq (2) | begin_hour (1) | end_hour (1) | length (4) | client_pubkey (64) |

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace logln {

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

} // namespace logln
