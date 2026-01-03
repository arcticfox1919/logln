// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include <gtest/gtest.h>

#include "../src/buffer.hpp"

#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace logln {
namespace {

// ============================================================================
// BufferView Tests
// ============================================================================

class BufferViewTest : public ::testing::Test {
protected:
    static constexpr std::size_t kBufferSize = 256;
    std::array<std::byte, kBufferSize> buffer_{};
};

TEST_F(BufferViewTest, DefaultConstruction) {
    BufferView view;
    
    EXPECT_EQ(view.data(), nullptr);
    EXPECT_EQ(view.size(), 0);
    EXPECT_EQ(view.capacity(), 0);
    EXPECT_EQ(view.write_pos(), 0);
    EXPECT_TRUE(view.empty());
    EXPECT_FALSE(view.is_attached());
}

TEST_F(BufferViewTest, ConstructWithExternalMemory) {
    BufferView view(buffer_.data(), 0, kBufferSize);
    
    EXPECT_EQ(view.data(), reinterpret_cast<std::byte*>(buffer_.data()));
    EXPECT_EQ(view.size(), 0);
    EXPECT_EQ(view.capacity(), kBufferSize);
    EXPECT_EQ(view.available(), kBufferSize);
    EXPECT_TRUE(view.is_attached());
}

TEST_F(BufferViewTest, ConstructWithExistingSize) {
    BufferView view(buffer_.data(), 100, kBufferSize);
    
    EXPECT_EQ(view.size(), 100);
    EXPECT_EQ(view.capacity(), kBufferSize);
    EXPECT_EQ(view.write_pos(), 0);
}

TEST_F(BufferViewTest, AttachDetach) {
    BufferView view;
    
    // Attach
    view.attach(buffer_.data(), kBufferSize);
    EXPECT_TRUE(view.is_attached());
    EXPECT_EQ(view.capacity(), kBufferSize);
    EXPECT_EQ(view.size(), 0);
    
    // Detach
    view.detach();
    EXPECT_FALSE(view.is_attached());
    EXPECT_EQ(view.data(), nullptr);
    EXPECT_EQ(view.capacity(), 0);
}

TEST_F(BufferViewTest, AttachWithSize) {
    BufferView view;
    view.attach(buffer_.data(), 50, kBufferSize);
    
    EXPECT_EQ(view.size(), 50);
    EXPECT_EQ(view.capacity(), kBufferSize);
}

TEST_F(BufferViewTest, WriteAtCurrentPosition) {
    BufferView view(buffer_.data(), 0, kBufferSize);
    
    const char* data = "Hello, World!";
    std::size_t len = std::strlen(data);
    
    std::size_t written = view.write(data, len);
    
    EXPECT_EQ(written, len);
    EXPECT_EQ(view.size(), len);
    EXPECT_EQ(view.write_pos(), len);
    EXPECT_EQ(std::memcmp(buffer_.data(), data, len), 0);
}

TEST_F(BufferViewTest, WriteAtSpecificPosition) {
    BufferView view(buffer_.data(), 0, kBufferSize);
    
    const char* data = "Test";
    std::size_t len = std::strlen(data);
    std::size_t pos = 100;
    
    std::size_t written = view.write(data, len, pos);
    
    EXPECT_EQ(written, len);
    EXPECT_EQ(view.size(), pos + len);
    EXPECT_EQ(view.write_pos(), 0);  // write_pos unchanged
    EXPECT_EQ(std::memcmp(buffer_.data() + pos, data, len), 0);
}

TEST_F(BufferViewTest, WriteSpan) {
    BufferView view(buffer_.data(), 0, kBufferSize);
    
    std::array<std::byte, 4> src = {
        std::byte{0x01}, std::byte{0x02}, 
        std::byte{0x03}, std::byte{0x04}
    };
    
    std::size_t written = view.write(std::span<const std::byte>(src));
    
    EXPECT_EQ(written, 4);
    EXPECT_EQ(view.size(), 4);
}

TEST_F(BufferViewTest, WriteOverflow) {
    constexpr std::size_t small_size = 10;
    std::array<std::byte, small_size> small_buffer{};
    BufferView view(small_buffer.data(), 0, small_size);
    
    const char* long_data = "This is a very long string that exceeds buffer capacity";
    std::size_t len = std::strlen(long_data);
    
    std::size_t written = view.write(long_data, len);
    
    EXPECT_EQ(written, small_size);
    EXPECT_EQ(view.size(), small_size);
}

TEST_F(BufferViewTest, SeekAndWritePos) {
    BufferView view(buffer_.data(), 0, kBufferSize);
    
    EXPECT_EQ(view.write_pos(), 0);
    
    view.seek(50);
    EXPECT_EQ(view.write_pos(), 50);
    
    // Seek beyond capacity should clamp
    view.seek(kBufferSize + 100);
    EXPECT_EQ(view.write_pos(), kBufferSize);
}

TEST_F(BufferViewTest, Reset) {
    BufferView view(buffer_.data(), 0, kBufferSize);
    
    view.write("test", 4);
    EXPECT_GT(view.size(), 0);
    
    view.reset();
    EXPECT_EQ(view.size(), 0);
    EXPECT_EQ(view.write_pos(), 0);
}

TEST_F(BufferViewTest, SetSize) {
    BufferView view(buffer_.data(), 0, kBufferSize);
    
    view.set_size(100);
    EXPECT_EQ(view.size(), 100);
    
    // Setting size beyond capacity should clamp
    view.set_size(kBufferSize + 100);
    EXPECT_EQ(view.size(), kBufferSize);
}

TEST_F(BufferViewTest, Available) {
    BufferView view(buffer_.data(), 0, kBufferSize);
    
    EXPECT_EQ(view.available(), kBufferSize);
    
    view.write("12345", 5);
    EXPECT_EQ(view.available(), kBufferSize - 5);
}

TEST_F(BufferViewTest, AsSpan) {
    BufferView view(buffer_.data(), 0, kBufferSize);
    
    const char* data = "Test data";
    view.write(data, std::strlen(data));
    
    auto span = view.as_span();
    EXPECT_EQ(span.size(), std::strlen(data));
    EXPECT_EQ(span.data(), view.data());
}

TEST_F(BufferViewTest, WriteToNullBuffer) {
    BufferView view;
    
    const char* data = "test";
    std::size_t written = view.write(data, 4);
    
    EXPECT_EQ(written, 0);
}

TEST_F(BufferViewTest, WriteNullData) {
    BufferView view(buffer_.data(), 0, kBufferSize);
    
    std::size_t written = view.write(nullptr, 10);
    
    EXPECT_EQ(written, 0);
}

// ============================================================================
// AutoBuffer Tests
// ============================================================================

class AutoBufferTest : public ::testing::Test {
protected:
    static constexpr std::size_t kInitialCapacity = 256;
};

TEST_F(AutoBufferTest, DefaultConstruction) {
    AutoBuffer buffer;
    
    EXPECT_EQ(buffer.ptr(), nullptr);
    EXPECT_EQ(buffer.length(), 0);
    EXPECT_EQ(buffer.capacity(), 0);
    EXPECT_EQ(buffer.pos(), 0);
    EXPECT_TRUE(buffer.empty());
}

TEST_F(AutoBufferTest, ConstructWithCapacity) {
    AutoBuffer buffer(kInitialCapacity);
    
    EXPECT_NE(buffer.ptr(), nullptr);
    EXPECT_GE(buffer.capacity(), kInitialCapacity);
    EXPECT_EQ(buffer.length(), 0);
}

TEST_F(AutoBufferTest, ConstructWithCapacity_Reserve) {
    AutoBuffer buffer(100);
    
    // Capacity should be at least 100
    EXPECT_GE(buffer.capacity(), 100);
    EXPECT_EQ(buffer.length(), 0);  // No data written yet
}

TEST_F(AutoBufferTest, WriteAutoExpands) {
    AutoBuffer buffer;
    
    const char* data = "Hello, World!";
    std::size_t len = std::strlen(data);
    
    buffer.write(data, len);
    
    EXPECT_EQ(buffer.length(), len);
    EXPECT_GE(buffer.capacity(), len);
    EXPECT_EQ(buffer.pos(), len);
    EXPECT_EQ(std::memcmp(buffer.ptr(), data, len), 0);
}

TEST_F(AutoBufferTest, WriteAtPosition) {
    AutoBuffer buffer;
    
    const char* data = "Test";
    std::size_t len = std::strlen(data);
    std::size_t pos = 100;
    
    buffer.write(pos, data, len);
    
    EXPECT_EQ(buffer.length(), pos + len);
    EXPECT_EQ(std::memcmp(buffer.ptr() + pos, data, len), 0);
}

TEST_F(AutoBufferTest, WriteSpan) {
    AutoBuffer buffer;
    
    std::array<std::byte, 4> src = {
        std::byte{0xAA}, std::byte{0xBB}, 
        std::byte{0xCC}, std::byte{0xDD}
    };
    
    buffer.write(std::span<const std::byte>(src));
    
    EXPECT_EQ(buffer.length(), 4);
}

TEST_F(AutoBufferTest, MultipleWrites) {
    AutoBuffer buffer;
    
    buffer.write("Hello", 5);
    buffer.write(", ", 2);
    buffer.write("World!", 6);
    
    EXPECT_EQ(buffer.length(), 13);
    EXPECT_EQ(std::memcmp(buffer.ptr(), "Hello, World!", 13), 0);
}

TEST_F(AutoBufferTest, Reset) {
    AutoBuffer buffer;
    buffer.write("test data", 9);
    
    buffer.reset();
    
    EXPECT_EQ(buffer.length(), 0);
    EXPECT_EQ(buffer.pos(), 0);
    // Note: vector::clear() preserves capacity
    EXPECT_GE(buffer.capacity(), 0);
}

TEST_F(AutoBufferTest, Clear) {
    AutoBuffer buffer;
    buffer.write("test data", 9);
    
    buffer.clear();
    
    EXPECT_EQ(buffer.length(), 0);
    // Note: shrink_to_fit is a hint, capacity may or may not be 0
}

TEST_F(AutoBufferTest, MoveConstruction) {
    AutoBuffer buffer1;
    buffer1.write("test", 4);
    std::size_t original_length = buffer1.length();
    
    AutoBuffer buffer2(std::move(buffer1));
    
    EXPECT_EQ(buffer2.length(), original_length);
    // After move, source is in valid but unspecified state
    // vector guarantees empty after move
    EXPECT_TRUE(buffer1.empty());
}

TEST_F(AutoBufferTest, MoveAssignment) {
    AutoBuffer buffer1;
    buffer1.write("test", 4);
    
    AutoBuffer buffer2;
    buffer2.write("other", 5);
    
    buffer2 = std::move(buffer1);
    
    EXPECT_EQ(buffer2.length(), 4);
    EXPECT_TRUE(buffer1.empty());
}

TEST_F(AutoBufferTest, Reserve) {
    AutoBuffer buffer;
    
    buffer.reserve(1000);
    
    EXPECT_GE(buffer.capacity(), 1000);
    EXPECT_EQ(buffer.length(), 0);  // Reserve doesn't change size
    
    // Write should not reallocate if within reserved capacity
    buffer.write("test", 4);
    EXPECT_GE(buffer.capacity(), 1000);
}

TEST_F(AutoBufferTest, Seek) {
    AutoBuffer buffer;
    
    buffer.write("12345", 5);
    EXPECT_EQ(buffer.pos(), 5);
    
    buffer.seek(2);
    EXPECT_EQ(buffer.pos(), 2);
    
    buffer.write("AB", 2);
    EXPECT_EQ(std::memcmp(buffer.ptr(), "12AB5", 5), 0);
}

TEST_F(AutoBufferTest, Available) {
    AutoBuffer buffer;
    buffer.reserve(100);
    
    buffer.write("12345", 5);
    EXPECT_GE(buffer.available(), 0);
}

TEST_F(AutoBufferTest, PosPtr) {
    AutoBuffer buffer;
    buffer.write("Hello", 5);
    
    EXPECT_EQ(buffer.pos_ptr(), buffer.ptr() + 5);
}

TEST_F(AutoBufferTest, DataAsSpan) {
    AutoBuffer buffer;
    buffer.write("test", 4);
    
    auto span = buffer.data();
    EXPECT_EQ(span.size(), 4);
    EXPECT_EQ(span.data(), buffer.ptr());
}

TEST_F(AutoBufferTest, WriteNullData) {
    AutoBuffer buffer;
    
    buffer.write(nullptr, 10);
    
    EXPECT_EQ(buffer.length(), 0);
}

TEST_F(AutoBufferTest, WriteZeroLength) {
    AutoBuffer buffer;
    
    buffer.write("test", 0);
    
    EXPECT_EQ(buffer.length(), 0);
}

TEST_F(AutoBufferTest, VectorGrowth) {
    AutoBuffer buffer;
    
    // First write should allocate
    buffer.write("a", 1);
    std::size_t cap1 = buffer.capacity();
    EXPECT_GE(cap1, 1);
    
    // Write more to trigger growth
    std::array<char, 1000> data{};
    buffer.write(data.data(), data.size());
    
    std::size_t cap2 = buffer.capacity();
    EXPECT_GE(cap2, 1001);
}

// ============================================================================
// MmapBuffer Tests
// ============================================================================

class MmapBufferTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temp directory for test files
        temp_dir_ = std::filesystem::temp_directory_path() / "logln_test";
        std::filesystem::create_directories(temp_dir_);
    }
    
    void TearDown() override {
        // Cleanup
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }
    
    std::filesystem::path temp_dir_;
};

TEST_F(MmapBufferTest, CreateNew) {
    auto path = temp_dir_ / "test_mmap.bin";
    
    auto result = MmapBuffer::create(path);
    
    ASSERT_TRUE(result.has_value());
    auto& buffer = *result;
    
    EXPECT_TRUE(buffer->is_mapped());
    EXPECT_EQ(buffer->capacity(), MmapBuffer::kDefaultBufferSize - 8);  // minus header
    EXPECT_EQ(buffer->size(), 0);
    EXPECT_TRUE(buffer->empty());
    EXPECT_EQ(buffer->path(), path);
}

TEST_F(MmapBufferTest, CreateWithCustomSize) {
    auto path = temp_dir_ / "test_mmap_custom.bin";
    constexpr std::size_t custom_size = 64 * 1024;
    
    auto result = MmapBuffer::create(path, custom_size);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ((*result)->capacity(), custom_size - 8);
}

TEST_F(MmapBufferTest, WriteData) {
    auto path = temp_dir_ / "test_write.bin";
    auto result = MmapBuffer::create(path);
    ASSERT_TRUE(result.has_value());
    auto& buffer = *result;
    
    const char* data = "Hello, MmapBuffer!";
    std::size_t len = std::strlen(data);
    
    std::size_t written = buffer->write(data, len);
    
    EXPECT_EQ(written, len);
    EXPECT_EQ(buffer->size(), len);
    EXPECT_EQ(std::memcmp(buffer->data(), data, len), 0);
}

TEST_F(MmapBufferTest, WriteSpan) {
    auto path = temp_dir_ / "test_write_span.bin";
    auto result = MmapBuffer::create(path);
    ASSERT_TRUE(result.has_value());
    auto& buffer = *result;
    
    std::array<std::byte, 4> src = {
        std::byte{0x11}, std::byte{0x22}, 
        std::byte{0x33}, std::byte{0x44}
    };
    
    std::size_t written = buffer->write(std::span<const std::byte>(src));
    
    EXPECT_EQ(written, 4);
    EXPECT_EQ(buffer->size(), 4);
}

TEST_F(MmapBufferTest, MultipleWrites) {
    auto path = temp_dir_ / "test_multi_write.bin";
    auto result = MmapBuffer::create(path);
    ASSERT_TRUE(result.has_value());
    auto& buffer = *result;
    
    buffer->write("First", 5);
    buffer->write("Second", 6);
    buffer->write("Third", 5);
    
    EXPECT_EQ(buffer->size(), 16);
}

TEST_F(MmapBufferTest, Clear) {
    auto path = temp_dir_ / "test_clear.bin";
    auto result = MmapBuffer::create(path);
    ASSERT_TRUE(result.has_value());
    auto& buffer = *result;
    
    buffer->write("test data", 9);
    EXPECT_GT(buffer->size(), 0);
    
    buffer->clear();
    
    EXPECT_EQ(buffer->size(), 0);
    EXPECT_TRUE(buffer->empty());
}

TEST_F(MmapBufferTest, FlushToAutoBuffer) {
    auto path = temp_dir_ / "test_flush.bin";
    auto result = MmapBuffer::create(path);
    ASSERT_TRUE(result.has_value());
    auto& buffer = *result;
    
    const char* data = "Flush test data";
    std::size_t len = std::strlen(data);
    buffer->write(data, len);
    
    AutoBuffer out;
    buffer->flush(out);
    
    EXPECT_EQ(out.length(), len);
    EXPECT_EQ(std::memcmp(out.ptr(), data, len), 0);
    // Note: flush() does NOT clear buffer (crash safety)
    // Caller should call clear() after successfully writing to file
    EXPECT_EQ(buffer->size(), len);
    
    // Explicitly clear
    buffer->clear();
    EXPECT_EQ(buffer->size(), 0);
}

TEST_F(MmapBufferTest, ViewAccess) {
    auto path = temp_dir_ / "test_view.bin";
    auto result = MmapBuffer::create(path);
    ASSERT_TRUE(result.has_value());
    auto& buffer = *result;
    
    BufferView& view = buffer->view();
    
    // Write through view
    view.write("via view", 8);
    
    EXPECT_EQ(buffer->size(), 8);
}

TEST_F(MmapBufferTest, Available) {
    auto path = temp_dir_ / "test_available.bin";
    auto result = MmapBuffer::create(path);
    ASSERT_TRUE(result.has_value());
    auto& buffer = *result;
    
    std::size_t initial_available = buffer->available();
    
    buffer->write("test", 4);
    
    EXPECT_EQ(buffer->available(), initial_available - 4);
}

TEST_F(MmapBufferTest, MoveConstruction) {
    auto path = temp_dir_ / "test_move.bin";
    auto result = MmapBuffer::create(path);
    ASSERT_TRUE(result.has_value());
    
    auto buffer1 = std::move(*result);
    buffer1->write("test", 4);
    
    MmapBuffer buffer2(std::move(*buffer1));
    
    EXPECT_TRUE(buffer2.is_mapped());
    EXPECT_EQ(buffer2.size(), 4);
}

TEST_F(MmapBufferTest, CrashRecovery) {
    auto path = temp_dir_ / "test_recovery.bin";
    
    // First: Create buffer and write data
    {
        auto result = MmapBuffer::create(path);
        ASSERT_TRUE(result.has_value());
        auto& buffer = *result;
        
        const char* data = "Recovery test data - important logs!";
        buffer->write(data, std::strlen(data));
        // Buffer destroyed without explicit flush - simulates crash
    }
    
    // Second: Reopen and recover
    {
        auto result = MmapBuffer::create(path);
        ASSERT_TRUE(result.has_value());
        auto& buffer = *result;
        
        auto recovered = buffer->recover();
        
        // Should recover the data
        EXPECT_GT(recovered.size(), 0);
        
        std::string recovered_str(
            reinterpret_cast<const char*>(recovered.data()), 
            recovered.size()
        );
        EXPECT_NE(recovered_str.find("Recovery test"), std::string::npos);
    }
}

TEST_F(MmapBufferTest, WriteOverflow) {
    auto path = temp_dir_ / "test_overflow.bin";
    constexpr std::size_t small_size = 64;  // Very small buffer
    
    auto result = MmapBuffer::create(path, small_size);
    ASSERT_TRUE(result.has_value());
    auto& buffer = *result;
    
    // Try to write more than capacity
    std::array<char, 100> large_data{};
    std::fill(large_data.begin(), large_data.end(), 'X');
    
    std::size_t written = buffer->write(large_data.data(), large_data.size());
    
    // Should only write up to capacity
    EXPECT_LT(written, large_data.size());
    EXPECT_EQ(written, buffer->capacity());
}

TEST_F(MmapBufferTest, InvalidPath) {
    // Try to create with invalid size (too small for header)
    auto path = temp_dir_ / "test_invalid_size.bin";
    
    // Size must be > kHeaderSize (8 bytes), so 0 or 8 should fail
    auto result = MmapBuffer::create(path, 0);
    EXPECT_FALSE(result.has_value());
    if (!result.has_value()) {
        EXPECT_EQ(result.error(), MmapBuffer::Error::InvalidSize);
    }
    
    auto result2 = MmapBuffer::create(path, 8);
    EXPECT_FALSE(result2.has_value());
    if (!result2.has_value()) {
        EXPECT_EQ(result2.error(), MmapBuffer::Error::InvalidSize);
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST(BufferIntegrationTest, BufferViewWithStackMemory) {
    std::array<std::byte, 128> stack_buffer{};
    BufferView view(stack_buffer.data(), 0, stack_buffer.size());
    
    view.write("Stack memory test", 17);
    
    EXPECT_EQ(view.size(), 17);
    EXPECT_EQ(view.capacity(), 128);
}

TEST(BufferIntegrationTest, BufferViewWithAutoBuffer) {
    AutoBuffer auto_buffer(256);
    
    // Use BufferView to wrap AutoBuffer's memory
    BufferView view(auto_buffer.ptr(), 0, auto_buffer.capacity());
    
    view.write("Wrapped write", 13);
    
    // Update AutoBuffer's state manually if needed
    EXPECT_EQ(view.size(), 13);
}

TEST(BufferIntegrationTest, AutoBufferLargeData) {
    AutoBuffer buffer;
    
    // Write 1MB of data
    constexpr std::size_t large_size = 1024 * 1024;
    std::vector<char> large_data(large_size, 'A');
    
    buffer.write(large_data.data(), large_data.size());
    
    EXPECT_EQ(buffer.length(), large_size);
    EXPECT_GE(buffer.capacity(), large_size);
}

TEST(BufferIntegrationTest, StreamlikeUsage) {
    AutoBuffer buffer;
    
    // Simulate log record writing
    const char* level = "[INFO]";
    const char* tag = "[MyApp]";
    const char* message = "Application started successfully";
    
    buffer.write(level, std::strlen(level));
    buffer.write(" ", 1);
    buffer.write(tag, std::strlen(tag));
    buffer.write(" ", 1);
    buffer.write(message, std::strlen(message));
    buffer.write("\n", 1);
    
    std::string result(reinterpret_cast<const char*>(buffer.ptr()), buffer.length());
    EXPECT_EQ(result, "[INFO] [MyApp] Application started successfully\n");
}

}  // namespace
}  // namespace logln
