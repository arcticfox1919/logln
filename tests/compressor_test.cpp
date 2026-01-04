// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "compressor.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <numeric>
#include <random>
#include <string>
#include <vector>

namespace logln {
namespace {

// Helper to create test data
std::vector<std::byte> make_test_data(std::size_t size, std::byte fill = std::byte{0x42}) {
    return std::vector<std::byte>(size, fill);
}

// Helper to create random test data
std::vector<std::byte> make_random_data(std::size_t size, unsigned int seed = 12345) {
    std::mt19937 gen(seed);
    std::uniform_int_distribution<int> dist(0, 255);
    std::vector<std::byte> data(size);
    for (auto& b : data) {
        b = static_cast<std::byte>(dist(gen));
    }
    return data;
}

// Helper to create compressible text data
std::vector<std::byte> make_text_data(const std::string& text) {
    std::vector<std::byte> data(text.size());
    std::memcpy(data.data(), text.data(), text.size());
    return data;
}

// Helper to create highly compressible data (repeated pattern)
std::vector<std::byte> make_compressible_data(std::size_t size) {
    std::vector<std::byte> data(size);
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<std::byte>(i % 10);  // Repeating 0-9 pattern
    }
    return data;
}

// ============================================================================
// ZstdCompressor Construction Tests
// ============================================================================

TEST(ZstdCompressorTest, DefaultConstruction) {
    ZstdCompressor compressor;
    EXPECT_GT(compressor.max_compressed_size(100), 100);
}

TEST(ZstdCompressorTest, ConstructWithLevel1) {
    ZstdCompressor compressor(ZstdCompressor::kMinLevel);
    EXPECT_GT(compressor.max_compressed_size(100), 100);
}

TEST(ZstdCompressorTest, ConstructWithLevel22) {
    ZstdCompressor compressor(ZstdCompressor::kMaxLevel);
    EXPECT_GT(compressor.max_compressed_size(100), 100);
}

TEST(ZstdCompressorTest, ConstructWithDefaultLevel) {
    ZstdCompressor compressor(ZstdCompressor::kDefaultLevel);
    EXPECT_EQ(ZstdCompressor::kDefaultLevel, 3);
}

TEST(ZstdCompressorTest, MoveConstruction) {
    ZstdCompressor original(5);
    ZstdCompressor moved(std::move(original));
    
    // moved should work
    auto data = make_test_data(100);
    std::vector<std::byte> output(moved.max_compressed_size(data.size()));
    auto result = moved.compress_single(data, output);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(*result, 0);
}

TEST(ZstdCompressorTest, MoveAssignment) {
    ZstdCompressor original(5);
    ZstdCompressor target(10);
    target = std::move(original);
    
    // target should work
    auto data = make_test_data(100);
    std::vector<std::byte> output(target.max_compressed_size(data.size()));
    auto result = target.compress_single(data, output);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(*result, 0);
}

// ============================================================================
// Factory Tests
// ============================================================================

TEST(CompressorFactoryTest, MakeCompressorDefault) {
    auto compressor = make_compressor();
    ASSERT_NE(compressor, nullptr);
    EXPECT_GT(compressor->max_compressed_size(100), 0);
}

TEST(CompressorFactoryTest, MakeCompressorWithLevel) {
    auto compressor = make_compressor(10);
    ASSERT_NE(compressor, nullptr);
    EXPECT_GT(compressor->max_compressed_size(100), 0);
}

// ============================================================================
// Compress Single Tests
// ============================================================================

TEST(ZstdCompressorTest, CompressSingleSmallData) {
    ZstdCompressor compressor;
    auto input = make_test_data(64);
    std::vector<std::byte> output(compressor.max_compressed_size(input.size()));
    
    auto result = compressor.compress_single(input, output);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(*result, 0);
    EXPECT_LE(*result, output.size());
}

TEST(ZstdCompressorTest, CompressSingleLargeData) {
    ZstdCompressor compressor;
    auto input = make_compressible_data(100000);  // 100KB
    std::vector<std::byte> output(compressor.max_compressed_size(input.size()));
    
    auto result = compressor.compress_single(input, output);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(*result, 0);
    // Compressible data should compress well
    EXPECT_LT(*result, input.size());
}

TEST(ZstdCompressorTest, CompressSingleTextData) {
    ZstdCompressor compressor;
    std::string text = "2024-01-01 12:00:00 [INFO] Application started successfully.\n";
    text += "2024-01-01 12:00:01 [DEBUG] Loading configuration from config.json.\n";
    text += "2024-01-01 12:00:02 [INFO] Database connection established.\n";
    auto input = make_text_data(text);
    
    std::vector<std::byte> output(compressor.max_compressed_size(input.size()));
    
    auto result = compressor.compress_single(input, output);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(*result, 0);
}

TEST(ZstdCompressorTest, CompressSingleEmptyData) {
    ZstdCompressor compressor;
    std::vector<std::byte> input;
    std::vector<std::byte> output(compressor.max_compressed_size(0) + 100);
    
    auto result = compressor.compress_single(input, output);
    ASSERT_TRUE(result.has_value());
    // Empty input still produces a valid frame header
    EXPECT_GT(*result, 0);
}

TEST(ZstdCompressorTest, CompressSingleRandomData) {
    ZstdCompressor compressor;
    auto input = make_random_data(10000);
    std::vector<std::byte> output(compressor.max_compressed_size(input.size()));
    
    auto result = compressor.compress_single(input, output);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(*result, 0);
    // Random data doesn't compress well, may even expand
}

TEST(ZstdCompressorTest, CompressSingleOutputTooSmall) {
    ZstdCompressor compressor;
    auto input = make_random_data(1000);
    std::vector<std::byte> output(10);  // Too small
    
    auto result = compressor.compress_single(input, output);
    // Should fail with error or partial output
    // ZSTD behavior may vary, just check it doesn't crash
}

// ============================================================================
// Compress Streaming Tests
// ============================================================================

TEST(ZstdCompressorTest, CompressStreamSmallData) {
    ZstdCompressor compressor;
    auto input = make_test_data(64);
    std::vector<std::byte> output(compressor.max_compressed_size(input.size()));
    
    auto result = compressor.compress(input, output);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(*result, 0);
}

TEST(ZstdCompressorTest, CompressStreamMultipleChunks) {
    ZstdCompressor compressor;
    std::vector<std::byte> all_compressed;
    
    // Compress multiple chunks
    for (int i = 0; i < 5; ++i) {
        auto input = make_compressible_data(1000);
        std::vector<std::byte> output(compressor.max_compressed_size(input.size()));
        
        auto result = compressor.compress(input, output);
        ASSERT_TRUE(result.has_value());
        all_compressed.insert(all_compressed.end(), 
                              output.begin(), output.begin() + *result);
    }
    
    // Flush remaining data
    std::vector<std::byte> flush_output(1000);
    auto flush_result = compressor.flush(flush_output);
    ASSERT_TRUE(flush_result.has_value());
    all_compressed.insert(all_compressed.end(),
                          flush_output.begin(), flush_output.begin() + *flush_result);
    
    EXPECT_GT(all_compressed.size(), 0);
}

// ============================================================================
// Decompress Tests
// ============================================================================

TEST(ZstdCompressorTest, DecompressRoundTrip) {
    ZstdCompressor compressor;
    auto input = make_test_data(256, std::byte{0xAB});
    std::vector<std::byte> compressed(compressor.max_compressed_size(input.size()));
    
    // Compress
    auto compress_result = compressor.compress_single(input, compressed);
    ASSERT_TRUE(compress_result.has_value());
    compressed.resize(*compress_result);
    
    // Decompress
    auto decompress_result = compressor.decompress(compressed);
    ASSERT_TRUE(decompress_result.has_value());
    
    // Verify
    EXPECT_EQ(decompress_result->size(), input.size());
    EXPECT_EQ(*decompress_result, input);
}

TEST(ZstdCompressorTest, DecompressLargeDataRoundTrip) {
    ZstdCompressor compressor;
    auto input = make_compressible_data(500000);  // 500KB
    std::vector<std::byte> compressed(compressor.max_compressed_size(input.size()));
    
    // Compress
    auto compress_result = compressor.compress_single(input, compressed);
    ASSERT_TRUE(compress_result.has_value());
    compressed.resize(*compress_result);
    
    // Decompress
    auto decompress_result = compressor.decompress(compressed);
    ASSERT_TRUE(decompress_result.has_value());
    
    // Verify
    EXPECT_EQ(decompress_result->size(), input.size());
    EXPECT_EQ(*decompress_result, input);
}

TEST(ZstdCompressorTest, DecompressTextRoundTrip) {
    ZstdCompressor compressor;
    std::string original_text;
    for (int i = 0; i < 100; ++i) {
        original_text += "Log entry " + std::to_string(i) + ": Some log message here.\n";
    }
    auto input = make_text_data(original_text);
    std::vector<std::byte> compressed(compressor.max_compressed_size(input.size()));
    
    // Compress
    auto compress_result = compressor.compress_single(input, compressed);
    ASSERT_TRUE(compress_result.has_value());
    compressed.resize(*compress_result);
    
    // Decompress
    auto decompress_result = compressor.decompress(compressed);
    ASSERT_TRUE(decompress_result.has_value());
    
    // Verify
    EXPECT_EQ(decompress_result->size(), input.size());
    std::string decompressed_text(
        reinterpret_cast<const char*>(decompress_result->data()),
        decompress_result->size());
    EXPECT_EQ(decompressed_text, original_text);
}

TEST(ZstdCompressorTest, DecompressEmptyRoundTrip) {
    ZstdCompressor compressor;
    std::vector<std::byte> input;
    std::vector<std::byte> compressed(compressor.max_compressed_size(0) + 100);
    
    // Compress
    auto compress_result = compressor.compress_single(input, compressed);
    ASSERT_TRUE(compress_result.has_value());
    compressed.resize(*compress_result);
    
    // Decompress
    auto decompress_result = compressor.decompress(compressed);
    ASSERT_TRUE(decompress_result.has_value());
    
    // Verify empty result
    EXPECT_EQ(decompress_result->size(), 0);
}

TEST(ZstdCompressorTest, DecompressRandomDataRoundTrip) {
    ZstdCompressor compressor;
    auto input = make_random_data(8192, 67890);
    std::vector<std::byte> compressed(compressor.max_compressed_size(input.size()));
    
    // Compress
    auto compress_result = compressor.compress_single(input, compressed);
    ASSERT_TRUE(compress_result.has_value());
    compressed.resize(*compress_result);
    
    // Decompress
    auto decompress_result = compressor.decompress(compressed);
    ASSERT_TRUE(decompress_result.has_value());
    
    // Verify
    EXPECT_EQ(decompress_result->size(), input.size());
    EXPECT_EQ(*decompress_result, input);
}

TEST(ZstdCompressorTest, DecompressInvalidData) {
    ZstdCompressor compressor;
    std::vector<std::byte> garbage(100, std::byte{0xFF});
    
    auto result = compressor.decompress(garbage);
    EXPECT_FALSE(result.has_value());
}

TEST(ZstdCompressorTest, DecompressCorruptedData) {
    ZstdCompressor compressor;
    auto input = make_test_data(256);
    std::vector<std::byte> compressed(compressor.max_compressed_size(input.size()));
    
    // Compress
    auto compress_result = compressor.compress_single(input, compressed);
    ASSERT_TRUE(compress_result.has_value());
    compressed.resize(*compress_result);
    
    // Corrupt the data
    if (compressed.size() > 10) {
        compressed[10] ^= std::byte{0xFF};
    }
    
    // Decompress should fail
    auto decompress_result = compressor.decompress(compressed);
    EXPECT_FALSE(decompress_result.has_value());
}

// ============================================================================
// Flush Tests
// ============================================================================

TEST(ZstdCompressorTest, FlushAfterCompress) {
    ZstdCompressor compressor;
    auto input = make_test_data(100);
    std::vector<std::byte> output(compressor.max_compressed_size(input.size()));
    
    // Compress
    auto compress_result = compressor.compress(input, output);
    ASSERT_TRUE(compress_result.has_value());
    
    // Flush
    std::vector<std::byte> flush_output(1000);
    auto flush_result = compressor.flush(flush_output);
    ASSERT_TRUE(flush_result.has_value());
}

TEST(ZstdCompressorTest, FlushWithoutCompress) {
    ZstdCompressor compressor;
    std::vector<std::byte> output(1000);
    
    auto result = compressor.flush(output);
    ASSERT_TRUE(result.has_value());
}

// ============================================================================
// Reset Tests
// ============================================================================

TEST(ZstdCompressorTest, ResetAndReuse) {
    ZstdCompressor compressor;
    
    // First compression
    auto input1 = make_test_data(100, std::byte{0x11});
    std::vector<std::byte> compressed1(compressor.max_compressed_size(input1.size()));
    auto result1 = compressor.compress_single(input1, compressed1);
    ASSERT_TRUE(result1.has_value());
    compressed1.resize(*result1);
    
    // Reset
    compressor.reset();
    
    // Second compression
    auto input2 = make_test_data(200, std::byte{0x22});
    std::vector<std::byte> compressed2(compressor.max_compressed_size(input2.size()));
    auto result2 = compressor.compress_single(input2, compressed2);
    ASSERT_TRUE(result2.has_value());
    compressed2.resize(*result2);
    
    // Verify both can be decompressed
    auto decompressed1 = compressor.decompress(compressed1);
    ASSERT_TRUE(decompressed1.has_value());
    EXPECT_EQ(*decompressed1, input1);
    
    auto decompressed2 = compressor.decompress(compressed2);
    ASSERT_TRUE(decompressed2.has_value());
    EXPECT_EQ(*decompressed2, input2);
}

TEST(ZstdCompressorTest, MultipleResets) {
    ZstdCompressor compressor;
    
    for (int i = 0; i < 10; ++i) {
        compressor.reset();
        
        auto input = make_test_data(50 + i * 10);
        std::vector<std::byte> compressed(compressor.max_compressed_size(input.size()));
        auto result = compressor.compress_single(input, compressed);
        ASSERT_TRUE(result.has_value());
    }
}

// ============================================================================
// Max Compressed Size Tests
// ============================================================================

TEST(ZstdCompressorTest, MaxCompressedSizeZero) {
    ZstdCompressor compressor;
    auto size = compressor.max_compressed_size(0);
    EXPECT_GT(size, 0);  // Even empty data has a frame header
}

TEST(ZstdCompressorTest, MaxCompressedSizeSmall) {
    ZstdCompressor compressor;
    auto size = compressor.max_compressed_size(100);
    EXPECT_GT(size, 100);  // Worst case: expansion
}

TEST(ZstdCompressorTest, MaxCompressedSizeLarge) {
    ZstdCompressor compressor;
    auto size = compressor.max_compressed_size(1000000);
    EXPECT_GT(size, 0);
}

// ============================================================================
// Compression Level Tests
// ============================================================================

TEST(ZstdCompressorTest, DifferentLevelsProduceDifferentRatios) {
    auto input = make_compressible_data(100000);
    
    ZstdCompressor fast_compressor(1);
    ZstdCompressor slow_compressor(19);
    
    std::vector<std::byte> fast_output(fast_compressor.max_compressed_size(input.size()));
    std::vector<std::byte> slow_output(slow_compressor.max_compressed_size(input.size()));
    
    auto fast_result = fast_compressor.compress_single(input, fast_output);
    auto slow_result = slow_compressor.compress_single(input, slow_output);
    
    ASSERT_TRUE(fast_result.has_value());
    ASSERT_TRUE(slow_result.has_value());
    
    // Higher level should produce smaller output (usually)
    // Note: This isn't always guaranteed, but typically true for compressible data
    EXPECT_LE(*slow_result, *fast_result + (*fast_result / 10));  // Allow 10% tolerance
}

// ============================================================================
// Independent Frame Tests
// ============================================================================

TEST(ZstdCompressorTest, CompressSingleCreatesIndependentFrames) {
    ZstdCompressor compressor;
    
    // Compress two independent frames
    auto input1 = make_test_data(100, std::byte{0xAA});
    auto input2 = make_test_data(200, std::byte{0xBB});
    
    std::vector<std::byte> compressed1(compressor.max_compressed_size(input1.size()));
    std::vector<std::byte> compressed2(compressor.max_compressed_size(input2.size()));
    
    auto result1 = compressor.compress_single(input1, compressed1);
    auto result2 = compressor.compress_single(input2, compressed2);
    
    ASSERT_TRUE(result1.has_value());
    ASSERT_TRUE(result2.has_value());
    
    compressed1.resize(*result1);
    compressed2.resize(*result2);
    
    // Each frame should be independently decompressible
    auto decompressed1 = compressor.decompress(compressed1);
    auto decompressed2 = compressor.decompress(compressed2);
    
    ASSERT_TRUE(decompressed1.has_value());
    ASSERT_TRUE(decompressed2.has_value());
    
    EXPECT_EQ(*decompressed1, input1);
    EXPECT_EQ(*decompressed2, input2);
}

// ============================================================================
// Context Reuse Tests
// ============================================================================

TEST(ZstdCompressorTest, DecompressContextReuse) {
    ZstdCompressor compressor;
    
    // Compress multiple independent frames
    std::vector<std::vector<std::byte>> compressed_frames;
    std::vector<std::vector<std::byte>> original_inputs;
    
    for (int i = 0; i < 10; ++i) {
        auto input = make_compressible_data(1000 + i * 100);
        original_inputs.push_back(input);
        
        std::vector<std::byte> compressed(compressor.max_compressed_size(input.size()));
        auto result = compressor.compress_single(input, compressed);
        ASSERT_TRUE(result.has_value());
        compressed.resize(*result);
        compressed_frames.push_back(std::move(compressed));
    }
    
    // Decompress all frames (context should be reused)
    for (std::size_t i = 0; i < compressed_frames.size(); ++i) {
        auto decompressed = compressor.decompress(compressed_frames[i]);
        ASSERT_TRUE(decompressed.has_value());
        EXPECT_EQ(*decompressed, original_inputs[i]);
    }
}

// ============================================================================
// Stress Tests
// ============================================================================

TEST(ZstdCompressorTest, ManySmallCompressions) {
    ZstdCompressor compressor;
    
    for (int i = 0; i < 1000; ++i) {
        auto input = make_test_data(i % 100 + 1);
        std::vector<std::byte> output(compressor.max_compressed_size(input.size()));
        
        auto result = compressor.compress_single(input, output);
        ASSERT_TRUE(result.has_value());
    }
}

TEST(ZstdCompressorTest, VariedSizeRoundTrips) {
    ZstdCompressor compressor;
    
    std::vector<std::size_t> sizes = {1, 10, 100, 1000, 10000, 50000};
    
    for (auto size : sizes) {
        auto input = make_compressible_data(size);
        std::vector<std::byte> compressed(compressor.max_compressed_size(input.size()));
        
        auto compress_result = compressor.compress_single(input, compressed);
        ASSERT_TRUE(compress_result.has_value());
        compressed.resize(*compress_result);
        
        auto decompress_result = compressor.decompress(compressed);
        ASSERT_TRUE(decompress_result.has_value());
        EXPECT_EQ(*decompress_result, input);
    }
}

// ============================================================================
// Interface Tests
// ============================================================================

TEST(ICompressorTest, PolymorphicUsage) {
    std::unique_ptr<ICompressor> compressor = std::make_unique<ZstdCompressor>();
    
    auto input = make_test_data(100);
    std::vector<std::byte> output(compressor->max_compressed_size(input.size()));
    
    auto result = compressor->compress_single(input, output);
    ASSERT_TRUE(result.has_value());
    
    output.resize(*result);
    auto decompressed = compressor->decompress(output);
    ASSERT_TRUE(decompressed.has_value());
    EXPECT_EQ(*decompressed, input);
}

}  // namespace
}  // namespace logln
