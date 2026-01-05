// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "log_buffer.hpp"
#include "buffer.hpp"
#include "compressor.hpp"
#include "encryptor.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>

namespace logln {
namespace {

// ============================================================================
// LogMagicNum Tests
// ============================================================================

TEST(LogMagicNumTest, MakeMagic) {
    EXPECT_EQ(LogMagicNum::make_magic(false, false), '\x06');
    EXPECT_EQ(LogMagicNum::make_magic(true,  false), '\x07');
    EXPECT_EQ(LogMagicNum::make_magic(false, true),  '\x08');
    EXPECT_EQ(LogMagicNum::make_magic(true,  true),  '\x09');
}

TEST(LogMagicNumTest, IsValidStart) {
    EXPECT_FALSE(LogMagicNum::is_valid_start('\x05'));
    EXPECT_TRUE(LogMagicNum::is_valid_start('\x06'));
    EXPECT_TRUE(LogMagicNum::is_valid_start('\x07'));
    EXPECT_TRUE(LogMagicNum::is_valid_start('\x08'));
    EXPECT_TRUE(LogMagicNum::is_valid_start('\x09'));
    EXPECT_FALSE(LogMagicNum::is_valid_start('\x0A'));
}

TEST(LogMagicNumTest, IsCompressed) {
    EXPECT_FALSE(LogMagicNum::is_compressed('\x06'));
    EXPECT_TRUE(LogMagicNum::is_compressed('\x07'));
    EXPECT_FALSE(LogMagicNum::is_compressed('\x08'));
    EXPECT_TRUE(LogMagicNum::is_compressed('\x09'));
}

TEST(LogMagicNumTest, IsEncrypted) {
    EXPECT_FALSE(LogMagicNum::is_encrypted('\x06'));
    EXPECT_FALSE(LogMagicNum::is_encrypted('\x07'));
    EXPECT_TRUE(LogMagicNum::is_encrypted('\x08'));
    EXPECT_TRUE(LogMagicNum::is_encrypted('\x09'));
}

// ============================================================================
// LogHeader Tests
// ============================================================================

class LogHeaderTest : public ::testing::Test {
protected:
    static constexpr std::size_t kBufferSize = 256;
    std::byte buffer_[kBufferSize]{};
};

TEST_F(LogHeaderTest, WriteHeader) {
    LogHeader header;
    header.write_header(buffer_, false, false);
    
    // Check magic
    EXPECT_EQ(static_cast<char>(buffer_[0]), '\x06');
    
    // Check seq (should be 1)
    std::uint16_t seq;
    std::memcpy(&seq, buffer_ + 1, sizeof(seq));
    EXPECT_EQ(seq, 1);
    
    // Check length (should be 0 initially)
    EXPECT_EQ(LogHeader::get_length(buffer_), 0u);
}

TEST_F(LogHeaderTest, WriteHeaderCompressed) {
    LogHeader header;
    header.write_header(buffer_, true, false);
    EXPECT_EQ(static_cast<char>(buffer_[0]), '\x07');
}

TEST_F(LogHeaderTest, WriteHeaderEncrypted) {
    LogHeader header;
    header.write_header(buffer_, false, true);
    EXPECT_EQ(static_cast<char>(buffer_[0]), '\x08');
}

TEST_F(LogHeaderTest, WriteHeaderBoth) {
    LogHeader header;
    header.write_header(buffer_, true, true);
    EXPECT_EQ(static_cast<char>(buffer_[0]), '\x09');
}

TEST_F(LogHeaderTest, SequenceIncrement) {
    LogHeader header;
    
    header.write_header(buffer_, false, false);
    std::uint16_t seq1;
    std::memcpy(&seq1, buffer_ + 1, sizeof(seq1));
    
    header.write_header(buffer_, false, false);
    std::uint16_t seq2;
    std::memcpy(&seq2, buffer_ + 1, sizeof(seq2));
    
    EXPECT_EQ(seq2, seq1 + 1);
}

TEST_F(LogHeaderTest, LengthOperations) {
    LogHeader header;
    header.write_header(buffer_, false, false);
    
    EXPECT_EQ(LogHeader::get_length(buffer_), 0u);
    
    LogHeader::set_length(buffer_, 100);
    EXPECT_EQ(LogHeader::get_length(buffer_), 100u);
    
    LogHeader::add_length(buffer_, 50);
    EXPECT_EQ(LogHeader::get_length(buffer_), 150u);
}

TEST_F(LogHeaderTest, WriteTailer) {
    LogHeader::write_tailer(buffer_);
    EXPECT_EQ(static_cast<char>(buffer_[0]), '\x00');
}

TEST_F(LogHeaderTest, ValidateAndGetLength) {
    LogHeader header;
    header.write_header(buffer_, false, false);
    LogHeader::set_length(buffer_, 50);
    
    std::uint32_t out_length = 0;
    EXPECT_TRUE(LogHeader::validate_and_get_length(buffer_, kBufferSize, out_length));
    EXPECT_EQ(out_length, 50u);
}

TEST_F(LogHeaderTest, ValidateInvalidMagic) {
    buffer_[0] = std::byte{0x05};  // Invalid magic
    
    std::uint32_t out_length = 0;
    EXPECT_FALSE(LogHeader::validate_and_get_length(buffer_, kBufferSize, out_length));
}

TEST_F(LogHeaderTest, ValidateBufferTooSmall) {
    LogHeader header;
    header.write_header(buffer_, false, false);
    
    std::uint32_t out_length = 0;
    EXPECT_FALSE(LogHeader::validate_and_get_length(buffer_, 10, out_length));  // Too small
}

TEST_F(LogHeaderTest, ClientPubKey) {
    LogHeader header;
    header.write_header(buffer_, false, true);
    
    // Set a test public key
    std::array<std::byte, 64> test_key;
    for (std::size_t i = 0; i < 64; ++i) {
        test_key[i] = static_cast<std::byte>(i);
    }
    
    LogHeader::set_client_pubkey(buffer_, test_key);
    
    auto retrieved = LogHeader::get_client_pubkey(buffer_);
    EXPECT_EQ(retrieved.size(), 64u);
    for (std::size_t i = 0; i < 64; ++i) {
        EXPECT_EQ(retrieved[i], test_key[i]);
    }
}

// ============================================================================
// LogBuffer Tests - Using Real MmapBuffer
// ============================================================================

class LogBufferTest : public ::testing::Test {
protected:
    void SetUp() override {
        temp_path_ = std::filesystem::temp_directory_path() / "logln_test_buffer.mmap";
        auto result = MmapBuffer::create(temp_path_, kBufferSize);
        ASSERT_TRUE(result.has_value()) << "Failed to create mmap buffer";
        mmap_ = std::move(*result);
    }
    
    void TearDown() override {
        mmap_.reset();
        std::error_code ec;
        std::filesystem::remove(temp_path_, ec);
    }
    
    static constexpr std::size_t kBufferSize = 4096;
    std::filesystem::path temp_path_;
    std::unique_ptr<MmapBuffer> mmap_;
};

// ============================================================================
// Plain Text Mode Tests
// ============================================================================

TEST_F(LogBufferTest, PlainTextConstruction) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, true);
    
    EXPECT_TRUE(buffer.is_plain_text_mode());
    EXPECT_FALSE(buffer.is_binary_mode());
    EXPECT_TRUE(buffer.empty());
}

TEST_F(LogBufferTest, PlainTextWrite) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, true);
    
    std::string_view msg = "Hello, World!";
    EXPECT_TRUE(buffer.write(msg));
    EXPECT_FALSE(buffer.empty());
    EXPECT_EQ(buffer.length(), msg.size());
}

TEST_F(LogBufferTest, PlainTextMultipleWrites) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, true);
    
    EXPECT_TRUE(buffer.write("First "));
    EXPECT_TRUE(buffer.write("Second "));
    EXPECT_TRUE(buffer.write("Third"));
    
    EXPECT_EQ(buffer.length(), 18u);  // "First Second Third"
}

TEST_F(LogBufferTest, PlainTextFlush) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, true);
    
    std::string_view msg = "Test message";
    (void)buffer.write(msg);
    
    AutoBuffer out;
    buffer.flush(out);

    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(out.length(), msg.size());
    EXPECT_EQ(std::memcmp(out.ptr(), msg.data(), msg.size()), 0);
}

TEST_F(LogBufferTest, PlainTextAvailable) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, true);
    
    std::size_t initial_avail = buffer.available();
    EXPECT_GT(initial_avail, 0u);
    
    (void)buffer.write("Some data");
    EXPECT_LT(buffer.available(), initial_avail);
}

TEST_F(LogBufferTest, PlainTextBufferFull) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, true);
    
    // Fill the buffer
    std::string large_data(buffer.available() + 100, 'X');
    EXPECT_FALSE(buffer.write(large_data));
}

TEST_F(LogBufferTest, PlainTextClear) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, true);
    
    (void)buffer.write("Some data");
    EXPECT_FALSE(buffer.empty());
    
    buffer.clear();
    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.length(), 0u);
}

// ============================================================================
// Binary Mode Tests (No Compression/Encryption)
// ============================================================================

TEST_F(LogBufferTest, BinaryModeConstruction) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, false);
    
    EXPECT_FALSE(buffer.is_plain_text_mode());
    EXPECT_TRUE(buffer.is_binary_mode());
}

TEST_F(LogBufferTest, BinaryModeWrite) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, false);
    
    std::string_view msg = "Binary mode test";
    EXPECT_TRUE(buffer.write(msg));
    EXPECT_FALSE(buffer.empty());
}

TEST_F(LogBufferTest, BinaryModeFlush) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, false);
    
    std::string_view msg = "Binary flush test";
    (void)buffer.write(msg);
    
    AutoBuffer out;
    buffer.flush(out);
    
    EXPECT_TRUE(buffer.empty());
    
    // Output should include header + data + tailer
    EXPECT_GT(out.length(), msg.size());
    EXPECT_GE(out.length(), LogHeader::kHeaderSize + msg.size() + LogHeader::kTailerSize);
    
    // Verify magic
    EXPECT_TRUE(LogMagicNum::is_valid_start(static_cast<char>(*out.ptr())));
}

TEST_F(LogBufferTest, BinaryModeReset) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, false);
    
    (void)buffer.write("Some data");
    buffer.reset();
    
    EXPECT_TRUE(buffer.empty());
}

// ============================================================================
// Write Sync Tests
// ============================================================================

TEST_F(LogBufferTest, WriteSyncPlainText) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, true);
    
    std::string_view msg = "Sync write test";
    AutoBuffer out;
    
    EXPECT_TRUE(buffer.write_sync(msg.data(), msg.size(), out));
    EXPECT_EQ(out.length(), msg.size());
    EXPECT_EQ(std::memcmp(out.ptr(), msg.data(), msg.size()), 0);
}

TEST_F(LogBufferTest, WriteSyncBinaryMode) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, false);
    
    std::string_view msg = "Sync binary test";
    AutoBuffer out;
    
    EXPECT_TRUE(buffer.write_sync(msg.data(), msg.size(), out));
    
    // Should include header + data + tailer
    EXPECT_GT(out.length(), msg.size());
    EXPECT_TRUE(LogMagicNum::is_valid_start(static_cast<char>(*out.ptr())));
}

// ============================================================================
// Crash Recovery Tests
// ============================================================================

TEST_F(LogBufferTest, RecoverFromValidData) {
    // First, write some data
    {
        LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, false);
        (void)buffer.write("Recovery test data");
        // Don't flush - simulate crash (data stays in mmap)
    }
    
    // Create new buffer on same mmap - should recover
    AutoBuffer recovered;
    {
        LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, false);
        // Constructor should have called recover()
        // The recover happens in constructor, let's verify by flushing
    }
    
    // Verify mmap has valid header
    std::uint32_t len = 0;
    EXPECT_TRUE(LogHeader::validate_and_get_length(
        static_cast<std::byte*>(mmap_->data()), 
        mmap_->capacity(), 
        len));
    EXPECT_GT(len, 0u);
}

TEST_F(LogBufferTest, RecoverFromEmptyBuffer) {
    // Clear mmap first
    std::memset(mmap_->data(), 0, mmap_->capacity());
    
    AutoBuffer recovered;
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, false);
    
    // Should not recover anything from empty buffer
    EXPECT_TRUE(buffer.empty());
}

// ============================================================================
// With Compression Tests
// ============================================================================

TEST_F(LogBufferTest, CompressedWrite) {
    ZstdCompressor compressor;
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), &compressor, nullptr, false);
    
    EXPECT_TRUE(buffer.has_compressor());
    EXPECT_FALSE(buffer.has_encryptor());
    
    // Write some compressible data
    std::string data(500, 'A');  // Highly compressible
    EXPECT_TRUE(buffer.write(data));
    
    AutoBuffer out;
    buffer.flush(out);
    
    // Verify magic indicates compression
    EXPECT_TRUE(LogMagicNum::is_compressed(static_cast<char>(*out.ptr())));
    
    // Compressed output should be smaller than original (for repetitive data)
    // Header + compressed_data + tailer < Header + original_data + tailer
    // This is probabilistic for compressible data
}

TEST_F(LogBufferTest, CompressedWriteSync) {
    ZstdCompressor compressor;
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), &compressor, nullptr, false);
    
    std::string data(500, 'B');
    AutoBuffer out;
    
    EXPECT_TRUE(buffer.write_sync(data.data(), data.size(), out));
    EXPECT_TRUE(LogMagicNum::is_compressed(static_cast<char>(*out.ptr())));
}

// ============================================================================
// With Encryption Tests
// ============================================================================

TEST_F(LogBufferTest, EncryptedWrite) {
    // Create encryptor with test server public key (128 hex chars)
    std::string server_pubkey_hex(128, '0');
    for (std::size_t i = 0; i < 128; ++i) {
        server_pubkey_hex[i] = "0123456789abcdef"[i % 16];
    }
    
    ChaCha20Encryptor encryptor(server_pubkey_hex);
    
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, &encryptor, false);
    
    EXPECT_FALSE(buffer.has_compressor());
    EXPECT_TRUE(buffer.has_encryptor());
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST_F(LogBufferTest, WriteEmptyData) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, true);
    
    EXPECT_TRUE(buffer.write("", 0));
    EXPECT_TRUE(buffer.write(nullptr, 0));
    EXPECT_TRUE(buffer.empty());
}

TEST_F(LogBufferTest, WriteNullptr) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, true);
    
    EXPECT_TRUE(buffer.write(nullptr, 100));  // Should return true but write nothing
    EXPECT_TRUE(buffer.empty());
}

TEST_F(LogBufferTest, CapacityAndLength) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, true);
    
    EXPECT_GT(buffer.capacity(), 0u);
    EXPECT_EQ(buffer.length(), 0u);
    
    (void)buffer.write("Test");
    EXPECT_EQ(buffer.length(), 4u);
    EXPECT_EQ(buffer.capacity(), mmap_->capacity());
}

TEST_F(LogBufferTest, MultipleFlushes) {
    LogBuffer buffer(mmap_->data(), mmap_->capacity(), nullptr, nullptr, true);
    
    AutoBuffer out1, out2;
    
    (void)buffer.write("First");
    buffer.flush(out1);
    EXPECT_EQ(out1.length(), 5u);

    (void)buffer.write("Second");
    buffer.flush(out2);
    EXPECT_EQ(out2.length(), 6u);
}

}  // namespace
}  // namespace logln
