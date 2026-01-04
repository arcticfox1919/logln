// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "compressor.hpp"

#include <zstd.h>

namespace logln {

struct ZstdCompressor::Impl {
    ZSTD_CCtx* cctx = nullptr;  // Compression context (reused)
    ZSTD_DCtx* dctx = nullptr;  // Decompression context (reused)
    int level = kDefaultLevel;
    
    Impl(int level_) : level(level_) {
        cctx = ZSTD_createCCtx();
        if (cctx) {
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level);
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, 16);
        }
        dctx = ZSTD_createDCtx();
    }
    
    ~Impl() {
        if (cctx) {
            ZSTD_freeCCtx(cctx);
        }
        if (dctx) {
            ZSTD_freeDCtx(dctx);
        }
    }
    
    Impl(Impl&& other) noexcept 
        : cctx(other.cctx), dctx(other.dctx), level(other.level) {
        other.cctx = nullptr;
        other.dctx = nullptr;
    }
    
    Impl& operator=(Impl&& other) noexcept {
        if (this != &other) {
            if (cctx) ZSTD_freeCCtx(cctx);
            if (dctx) ZSTD_freeDCtx(dctx);
            cctx = other.cctx;
            dctx = other.dctx;
            level = other.level;
            other.cctx = nullptr;
            other.dctx = nullptr;
        }
        return *this;
    }
};

ZstdCompressor::ZstdCompressor(int level)
    : impl_(std::make_unique<Impl>(level)) {
}

ZstdCompressor::~ZstdCompressor() = default;

ZstdCompressor::ZstdCompressor(ZstdCompressor&&) noexcept = default;
ZstdCompressor& ZstdCompressor::operator=(ZstdCompressor&&) noexcept = default;

std::expected<std::size_t, int>
ZstdCompressor::compress(std::span<const std::byte> input, 
                         std::span<std::byte> output) {
    if (!impl_->cctx) {
        return std::unexpected(-1);
    }
    
    ZSTD_inBuffer in_buf = {
        input.data(),
        input.size(),
        0
    };
    
    ZSTD_outBuffer out_buf = {
        output.data(),
        output.size(),
        0
    };
    
    // Use ZSTD_e_flush for streaming compression
    // This produces better compression ratio across multiple records
    std::size_t result = ZSTD_compressStream2(
        impl_->cctx, &out_buf, &in_buf, ZSTD_e_flush);
    
    if (ZSTD_isError(result)) {
        return std::unexpected(static_cast<int>(result));
    }
    
    return out_buf.pos;
}

std::expected<std::size_t, int>
ZstdCompressor::compress_single(std::span<const std::byte> input, 
                                std::span<std::byte> output) {
    if (!impl_->cctx) {
        return std::unexpected(-1);
    }
    
    ZSTD_inBuffer in_buf = {
        input.data(),
        input.size(),
        0
    };
    
    ZSTD_outBuffer out_buf = {
        output.data(),
        output.size(),
        0
    };
    
    // Use ZSTD_e_end to create independent frame
    // Each compressed block can be decompressed independently
    std::size_t result = ZSTD_compressStream2(
        impl_->cctx, &out_buf, &in_buf, ZSTD_e_end);
    
    if (ZSTD_isError(result)) {
        return std::unexpected(static_cast<int>(result));
    }
    
    // Reset for next independent frame
    ZSTD_CCtx_reset(impl_->cctx, ZSTD_reset_session_only);
    
    return out_buf.pos;
}

std::expected<std::size_t, int>
ZstdCompressor::flush(std::span<std::byte> output) {
    if (!impl_->cctx) {
        return std::unexpected(-1);
    }
    
    ZSTD_inBuffer in_buf = {nullptr, 0, 0};
    ZSTD_outBuffer out_buf = {
        output.data(),
        output.size(),
        0
    };
    
    std::size_t result = ZSTD_compressStream2(
        impl_->cctx, &out_buf, &in_buf, ZSTD_e_end);
    
    if (ZSTD_isError(result)) {
        return std::unexpected(static_cast<int>(result));
    }
    
    return out_buf.pos;
}

void ZstdCompressor::reset() {
    if (impl_->cctx) {
        ZSTD_CCtx_reset(impl_->cctx, ZSTD_reset_session_only);
    }
}

std::size_t ZstdCompressor::max_compressed_size(std::size_t input_size) const {
    return ZSTD_compressBound(input_size);
}

std::expected<std::vector<std::byte>, int>
ZstdCompressor::decompress(std::span<const std::byte> input) {
    if (!impl_->dctx) {
        return std::unexpected(-1);
    }
    
    // Reset decompression context for new frame
    ZSTD_DCtx_reset(impl_->dctx, ZSTD_reset_session_only);
    
    // Estimate initial output size
    std::size_t out_capacity = input.size() * 10;  // Assume 10x expansion ratio
    std::vector<std::byte> output(out_capacity);
    
    ZSTD_inBuffer in_buf = {input.data(), input.size(), 0};
    ZSTD_outBuffer out_buf = {output.data(), output.size(), 0};
    
    // Decompress all input
    while (in_buf.pos < in_buf.size) {
        std::size_t result = ZSTD_decompressStream(impl_->dctx, &out_buf, &in_buf);
        
        if (ZSTD_isError(result)) {
            fprintf(stderr, "[ZSTD ERROR] %s (in_pos=%zu/%zu, out_pos=%zu/%zu)\n",
                    ZSTD_getErrorName(result), in_buf.pos, in_buf.size, out_buf.pos, out_buf.size);
            return std::unexpected(static_cast<int>(result));
        }
        
        // If output buffer is full, expand it
        if (out_buf.pos == out_buf.size && in_buf.pos < in_buf.size) {
            std::size_t new_capacity = output.size() * 2;
            output.resize(new_capacity);
            out_buf.dst = output.data();
            out_buf.size = output.size();
        }
    }
    
    output.resize(out_buf.pos);
    return output;
}

std::unique_ptr<ICompressor> make_compressor(int level) {
    return std::make_unique<ZstdCompressor>(level);
}

} // namespace logln

