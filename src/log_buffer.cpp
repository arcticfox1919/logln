// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "log_buffer.hpp"
#include "compressor.hpp"
#include "encryptor.hpp"

#include <cassert>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <vector>

namespace logln {

// ============================================================================
// Helper: Get current hour (0-23)
// ============================================================================

namespace {

[[nodiscard]] inline char get_current_hour() noexcept {
    auto ts = Timestamp::now();
    std::time_t sec = static_cast<std::time_t>(ts.tv_sec);
    std::tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &sec);
#else
    localtime_r(&sec, &tm_buf);
#endif
    return static_cast<char>(tm_buf.tm_hour);
}

}  // namespace

// ============================================================================
// LogHeader Implementation
// ============================================================================

std::uint16_t LogHeader::next_seq() noexcept {
    ++seq_;
    if (seq_ == 0) {
        seq_ = 1;  // Avoid 0 as it might indicate uninitialized
    }
    return seq_;
}

void LogHeader::write_header(std::byte* buffer,
                              bool compressed, bool encrypted) noexcept {
    char* data = reinterpret_cast<char*>(buffer);
    
    // magic (1 byte)
    data[0] = LogMagicNum::make_magic(compressed, encrypted);
    
    // seq (2 bytes)
    std::uint16_t seq = next_seq();
    std::memcpy(data + 1, &seq, sizeof(seq));
    
    // begin_hour (1 byte)
    char hour = get_current_hour();
    data[3] = hour;
    
    // end_hour (1 byte)
    data[4] = hour;
    
    // length (4 bytes) - initially 0
    std::uint32_t len = 0;
    std::memcpy(data + 5, &len, sizeof(len));
    
    // client_pubkey (64 bytes) - zero fill initially, set later if encrypted
    std::memset(data + 9, 0, 64);
    
    // nonce (16 bytes) - zero fill initially, set later if encrypted
    std::memset(data + 73, 0, 16);
}

void LogHeader::write_tailer(std::byte* buffer) noexcept {
    *reinterpret_cast<char*>(buffer) = LogMagicNum::kMagicEnd;
}

void LogHeader::set_client_pubkey(std::byte* header,
                                   std::span<const std::byte> pubkey) noexcept {
    if (pubkey.size() >= kClientPubKeySize) {
        std::memcpy(reinterpret_cast<char*>(header) + kClientPubKeyOffset,
                   pubkey.data(), kClientPubKeySize);
    }
}

std::span<const std::byte> LogHeader::get_client_pubkey(
    const std::byte* header) noexcept {
    return std::span<const std::byte>(header + kClientPubKeyOffset, kClientPubKeySize);
}

void LogHeader::set_nonce(std::byte* header,
                          std::span<const std::byte> nonce) noexcept {
    if (nonce.size() >= kNonceSize) {
        std::memcpy(reinterpret_cast<char*>(header) + kNonceOffset,
                   nonce.data(), kNonceSize);
    }
}

std::span<const std::byte> LogHeader::get_nonce(
    const std::byte* header) noexcept {
    return std::span<const std::byte>(header + kNonceOffset, kNonceSize);
}

void LogHeader::add_length(std::byte* header, std::uint32_t add_len) noexcept {
    std::uint32_t current = get_length(header);
    set_length(header, current + add_len);
}

void LogHeader::set_length(std::byte* header, std::uint32_t len) noexcept {
    std::memcpy(reinterpret_cast<char*>(header) + 5, &len, sizeof(len));
}

std::uint32_t LogHeader::get_length(const std::byte* header) noexcept {
    std::uint32_t len = 0;
    std::memcpy(&len, reinterpret_cast<const char*>(header) + 5, sizeof(len));
    return len;
}

void LogHeader::update_end_hour(std::byte* header) noexcept {
    reinterpret_cast<char*>(header)[4] = get_current_hour();
}

bool LogHeader::validate_and_get_length(const std::byte* header,
                                         std::size_t buffer_size,
                                         std::uint32_t& out_length) noexcept {
    if (buffer_size < kHeaderSize) {
        return false;
    }
    
    char magic = *reinterpret_cast<const char*>(header);
    if (!LogMagicNum::is_valid_start(magic)) {
        return false;
    }
    
    out_length = get_length(header);
    
    // Validate length is reasonable
    if (out_length > buffer_size - kHeaderSize - kTailerSize) {
        return false;
    }
    
    return true;
}

// ============================================================================
// LogBuffer Implementation
// ============================================================================

LogBuffer::LogBuffer(void* buffer, std::size_t size,
                     ICompressor* compressor,
                     IEncryptor* encryptor,
                     bool plain_text_mode)
    : compressor_(compressor)
    , encryptor_(encryptor)
    , initialized_(false)
    , plain_text_mode_(plain_text_mode) {
    view_.attach(buffer, size);
    
    // Try to recover from previous crash (only for binary mode)
    if (is_binary_mode()) {
        AutoBuffer dummy;
        if (!recover(dummy)) {
            // No valid data to recover, just clear
            clear();
        }
    } else {
        // Plain text mode: just clear
        clear();
    }
}

bool LogBuffer::write(const void* data, std::size_t len) {
    if (!data || len == 0) {
        return true;  // Nothing to write is success
    }
    
    // Plain text mode: direct write without headers
    if (is_plain_text_mode()) {
        std::size_t avail = view_.capacity() - view_.size();
        if (avail < len) {
            return false;  // Buffer full
        }
        std::byte* write_pos = view_.data() + view_.size();
        std::memcpy(write_pos, data, len);
        view_.set_size(view_.size() + len);
        return true;
    }
    
    // Binary mode: with protocol headers
    ensure_initialized();
    
    std::size_t avail = available();
    if (avail == 0) {
        return false;  // Buffer full
    }
    
    std::size_t before_len = view_.size();
    std::size_t write_len = len;
    
    // Step 1: Compress data if compressor available
    if (compressor_) {
        std::byte* write_pos = view_.data() + before_len;
        auto compress_result = compressor_->compress(
            std::span<const std::byte>(static_cast<const std::byte*>(data), len),
            std::span<std::byte>(write_pos, avail)
        );
        if (!compress_result) {
            return false;
        }
        write_len = *compress_result;
        // Temporarily update buffer length for encryption step
        view_.set_size(before_len + write_len);
    } else {
        // No compression - write directly to buffer
        std::byte* write_pos = view_.data() + before_len;
        write_len = std::min(len, avail);
        std::memcpy(write_pos, data, write_len);
        view_.set_size(before_len + write_len);
    }
    
    // Step 2: Streaming encryption (ChaCha20)
    if (encryptor_ && encryptor_->is_active()) {
        // Go back to include previous unencrypted bytes
        std::size_t encrypt_start_pos = before_len - remain_nocrypt_len_;
        std::byte* encrypt_start = view_.data() + encrypt_start_pos;
        std::size_t encrypt_input_len = write_len + remain_nocrypt_len_;
        std::size_t last_remain_len = remain_nocrypt_len_;
        
        // Encrypt full 8-byte blocks, leave remainder unencrypted
        std::size_t block_count = encrypt_input_len / 8;
        std::size_t new_remain_len = encrypt_input_len % 8;
        
        // Encrypt blocks in-place
        for (std::size_t i = 0; i < block_count; ++i) {
            auto block_span = std::span<std::byte>(encrypt_start + i * 8, 8);
            auto result = encryptor_->encrypt(block_span, block_span);
            if (!result) {
                // Rollback
                view_.set_size(before_len);
                return false;
            }
        }
        
        // Remainder stays unencrypted
        // Already in buffer, no need to move
        
        // Update buffer length to actual position
        view_.set_size(encrypt_start_pos + encrypt_input_len);
        
        // Update header length: net increase = (encrypted_input_len - last_remain_len)
        // This is the number of NEW encrypted bytes added to the log
        LogHeader::add_length(view_.data(), 
                            static_cast<std::uint32_t>(encrypt_input_len - last_remain_len));
        
        // Update remain for next write
        remain_nocrypt_len_ = new_remain_len;
    } else {
        // No encryption - just update header length
        LogHeader::add_length(view_.data(), static_cast<std::uint32_t>(write_len));
    }
    
    return true;
}

bool LogBuffer::write(std::string_view data) {
    return write(data.data(), data.size());
}

bool LogBuffer::write_sync(const void* data, std::size_t len, AutoBuffer& out) {
    if (!data || len == 0) {
        return false;
    }
    
    out.reset();
    
    // Plain text mode: direct write without protocol headers
    if (is_plain_text_mode()) {
        out.write(data, len);
        return true;
    }
    
    // Binary mode: with protocol headers
    // Calculate required size for temp buffer
    std::size_t processed_size = len;
    
    if (compressor_) {
        processed_size = compressor_->max_compressed_size(len);
    }
    
    // Write header
    std::byte header_buf[LogHeader::kHeaderSize];
    LogHeader temp_header;
    temp_header.write_header(
        header_buf,
        has_compressor(),
        false   // Sync mode does not support encryption
    );
    
    // NOTE: Sync mode does not use client pubkey (no streaming encryption)
    
    out.write(header_buf, LogHeader::kHeaderSize);
    
    // Process data - we need a temp buffer for compression
    std::vector<std::byte> temp_buf(processed_size);
    std::size_t written = 0;
    
    if (compressor_) {
        written = process_data(data, len, temp_buf.data(), temp_buf.size());
        if (written == 0) {
            out.reset();
            return false;
        }
        out.write(temp_buf.data(), written);
    } else {
        out.write(data, len);
        written = len;
    }
    
    // Update length in header (write back to the beginning)
    LogHeader::set_length(out.ptr(), static_cast<std::uint32_t>(written));
    
    // Write tailer
    std::byte tailer = static_cast<std::byte>(LogMagicNum::kMagicEnd);
    out.write(&tailer, LogHeader::kTailerSize);
    
    return true;
}

void LogBuffer::flush(AutoBuffer& out) {
    if (empty()) {
        return;
    }
    
    // Plain text mode: direct copy without protocol overhead
    if (is_plain_text_mode()) {
        out.write(view_.data(), view_.size());
        clear();
        return;
    }
    
    // Binary mode: finalize and copy
    // Finalize (add tailer, update hour)
    finalize();
    
    // Copy to output buffer 
    out.write(view_.data(), view_.size());
    
    // Clear mmap buffer (clear after copy)
    clear();
}

bool LogBuffer::empty() const noexcept {
    // Plain text mode: just check size
    if (is_plain_text_mode()) {
        return view_.size() == 0;
    }
    
    // Binary mode: check header length
    if (!initialized_) {
        return true;
    }
    return LogHeader::get_length(view_.data()) == 0;
}

std::size_t LogBuffer::length() const noexcept {
    return view_.size();
}

std::size_t LogBuffer::capacity() const noexcept {
    return view_.capacity();
}

std::size_t LogBuffer::available() const noexcept {
    // Plain text mode: simple calculation
    if (is_plain_text_mode()) {
        std::size_t used = view_.size();
        std::size_t total = view_.capacity();
        return (used < total) ? (total - used) : 0;
    }
    
    // Binary mode: account for header and tailer
    if (!initialized_) {
        return view_.capacity() - LogHeader::kHeaderSize - LogHeader::kTailerSize;
    }
    std::size_t used = view_.size();
    std::size_t total = view_.capacity();
    if (used + LogHeader::kTailerSize >= total) {
        return 0;
    }
    return total - used - LogHeader::kTailerSize;
}

bool LogBuffer::recover(AutoBuffer& out) {
    std::uint32_t data_len = 0;
    if (!LogHeader::validate_and_get_length(view_.data(), view_.capacity(), data_len)) {
        return false;
    }
    
    if (data_len == 0) {
        return false;
    }
    
    // Valid data found - copy to output
    std::size_t total_len = LogHeader::kHeaderSize + data_len;
    
    // Add tailer for completeness
    LogHeader::write_tailer(view_.data() + total_len);
    total_len += LogHeader::kTailerSize;
    
    out.write(view_.data(), total_len);
    
    // Mark as initialized since we found valid data
    initialized_ = true;
    view_.set_size(LogHeader::kHeaderSize + data_len);
    
    return true;
}

void LogBuffer::reset() {
    clear();
    // Only initialize header for binary mode
    if (is_binary_mode()) {
        ensure_initialized();
    }
}

void LogBuffer::clear() noexcept {
    // Only clear used portion for efficiency
    std::size_t clear_size = view_.size();
    if (clear_size > 0) {
        std::memset(view_.data(), 0, clear_size);
    }
    view_.set_size(0);
    initialized_ = false;
    
    // Reset encryption state for new block
    // BLOCK-INDEPENDENT ENCRYPTION: Each block starts with counter=0
    // This ensures crash-safety - no need to persist counter state
    remain_nocrypt_len_ = 0;
    if (encryptor_ && encryptor_->is_active()) {
        // Reset counter by re-setting the nonce
        auto nonce = encryptor_->nonce();
        encryptor_->set_nonce(nonce);
    }
}

std::size_t LogBuffer::process_data(const void* src, std::size_t len,
                                     void* dst, std::size_t dst_size) {
    std::size_t result_len = len;
    
    // Step 1: Compress if compressor available
    if (compressor_) {
        auto compress_result = compressor_->compress(
            std::span<const std::byte>(
                static_cast<const std::byte*>(src), len),
            std::span<std::byte>(
                static_cast<std::byte*>(dst), dst_size)
        );
        
        if (!compress_result) {
            return 0;  // Compression failed
        }
        
        result_len = *compress_result;
    } else {
        // No compression - copy data
        if (dst != src) {
            std::memcpy(dst, src, len);
        }
        result_len = len;
    }
    
    // NOTE: Sync mode does NOT encrypt data.
    // Encryption requires maintaining stream state (remain_nocrypt_len_),
    // which is only possible in async mode where data accumulates in a buffer.
    // If encryption is needed, use WriteMode::Async.
    
    return result_len;
}

char LogBuffer::get_magic() const noexcept {
    return LogMagicNum::make_magic(
        has_compressor(),
        has_encryptor()
    );
}

void LogBuffer::finalize() {
    if (!initialized_) {
        return;
    }
    
    // Update end hour
    LogHeader::update_end_hour(view_.data());
    
    // Add tailer
    LogHeader::write_tailer(view_.data() + view_.size());
    view_.set_size(view_.size() + LogHeader::kTailerSize);
}

void LogBuffer::ensure_initialized() {
    if (initialized_) {
        return;
    }
    
    // Write header
    header_.write_header(
        view_.data(),
        has_compressor(),
        has_encryptor()
    );
    
    // BLOCK-INDEPENDENT ENCRYPTION:
    // Every block stores its own pubkey and nonce for independent decryption
    // This is crash-safe: if process dies, each block can still be decoded
    // Counter resets to 0 at clear() for each new block
    if (encryptor_ && encryptor_->is_active()) {
        LogHeader::set_client_pubkey(view_.data(), encryptor_->public_key());
        LogHeader::set_nonce(view_.data(), encryptor_->nonce());
    }
    
    view_.set_size(LogHeader::kHeaderSize);
    initialized_ = true;
}

} // namespace logln
