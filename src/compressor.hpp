// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#pragma once

#include <cstddef>
#include <span>
#include <memory>
#include <expected>
#include <vector>

namespace logln {

// ============================================================================
// Compressor Interface
// ============================================================================

class ICompressor {
public:
    virtual ~ICompressor() = default;
    
    // Compress data (streaming mode - uses ZSTD_e_flush)
    // Use this when data is part of a continuous stream
    // Returns: number of bytes written to output, or error
    [[nodiscard]] virtual std::expected<std::size_t, int>
    compress(std::span<const std::byte> input, 
             std::span<std::byte> output) = 0;
    
    // Compress data as independent frame (uses ZSTD_e_end)
    // Use this when each record should be independently decompressible
    // (e.g., when combined with encryption)
    // Returns: number of bytes written to output, or error
    [[nodiscard]] virtual std::expected<std::size_t, int>
    compress_single(std::span<const std::byte> input, 
                    std::span<std::byte> output) = 0;
    
    // Decompress data
    // Returns: decompressed data or error
    [[nodiscard]] virtual std::expected<std::vector<std::byte>, int>
    decompress(std::span<const std::byte> input) = 0;
    
    // Flush any remaining data in internal buffers
    [[nodiscard]] virtual std::expected<std::size_t, int>
    flush(std::span<std::byte> output) = 0;
    
    // Reset compressor state for new stream
    virtual void reset() = 0;
    
    // Get maximum compressed size for input size
    [[nodiscard]] virtual std::size_t max_compressed_size(std::size_t input_size) const = 0;
};

// ============================================================================
// Zstd Compressor
// ============================================================================

class ZstdCompressor : public ICompressor {
public:
    // Compression level: 1 (fast) to 22 (best)
    // Level 3 is recommended for real-time logging 
    static constexpr int kDefaultLevel = 3;
    static constexpr int kMinLevel = 1;
    static constexpr int kMaxLevel = 22;
    
    explicit ZstdCompressor(int level = kDefaultLevel);
    ~ZstdCompressor() override;
    
    // Non-copyable
    ZstdCompressor(const ZstdCompressor&) = delete;
    ZstdCompressor& operator=(const ZstdCompressor&) = delete;
    
    // Movable
    ZstdCompressor(ZstdCompressor&&) noexcept;
    ZstdCompressor& operator=(ZstdCompressor&&) noexcept;
    
    // ICompressor interface
    [[nodiscard]] std::expected<std::size_t, int>
    compress(std::span<const std::byte> input, 
             std::span<std::byte> output) override;
    
    [[nodiscard]] std::expected<std::size_t, int>
    compress_single(std::span<const std::byte> input, 
                    std::span<std::byte> output) override;
    
    [[nodiscard]] std::expected<std::vector<std::byte>, int>
    decompress(std::span<const std::byte> input) override;
    
    [[nodiscard]] std::expected<std::size_t, int>
    flush(std::span<std::byte> output) override;
    
    void reset() override;
    
    [[nodiscard]] std::size_t max_compressed_size(std::size_t input_size) const override;
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Factory
// ============================================================================

[[nodiscard]] std::unique_ptr<ICompressor> make_compressor(int level = ZstdCompressor::kDefaultLevel);

} // namespace logln
