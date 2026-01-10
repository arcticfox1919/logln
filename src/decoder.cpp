// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "logln/decoder.h"
#include "compressor.hpp"
#include "encryptor.hpp"
#include "log_buffer.hpp"
#include "utils.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <cstring>
#include <span>
#include <expected>
#include <memory>

namespace logln {

// ============================================================================
// Header Parsing
// ============================================================================

LogDecoder::ParseResult LogDecoder::parse_header(std::span<const std::byte> data) {
    ParseResult result;
    
    if (data.size() < LogHeader::kHeaderSize + LogHeader::kTailerSize) {
        return result;
    }
    
    const auto* header = data.data();
    char magic = static_cast<char>(header[0]);
    
    if (!LogMagicNum::is_valid_start(magic)) {
        return result;
    }
    
    std::uint32_t length = 0;
    if (!LogHeader::validate_and_get_length(header, data.size(), length)) {
        return result;
    }
    
    result.valid = true;
    result.data_offset = LogHeader::kHeaderSize;
    result.data_length = length;
    result.is_compressed = LogMagicNum::is_compressed(magic);
    result.is_encrypted = LogMagicNum::is_encrypted(magic);
    
    return result;
}

// ============================================================================
// Data Processing (Decompress/Decrypt)
// ============================================================================

std::expected<std::vector<std::byte>, DecodeError> 
LogDecoder::process_data(std::span<const std::byte> data, const Options& opts,
                         bool is_compressed, bool is_encrypted) {
    std::vector<std::byte> result(data.begin(), data.end());
    
    // Decrypt first (reverse order of encoding)
    // IMPORTANT: Decryption must be done in 8-byte blocks to match the
    // encryption process in LogBuffer::write(), which encrypts each 8-byte
    // block with an incrementing counter.
    if (is_encrypted && opts.encryptor) {
        constexpr std::size_t kBlockSize = 8;
        std::size_t block_count = result.size() / kBlockSize;
        
        for (std::size_t i = 0; i < block_count; ++i) {
            auto block = std::span<std::byte>(result.data() + i * kBlockSize, kBlockSize);
            auto decrypted = opts.encryptor->decrypt(block);
            if (!decrypted) {
                return std::unexpected(DecodeError::DecryptFailed);
            }
            std::copy(decrypted->begin(), decrypted->end(), block.begin());
        }
        
        // Note: Any trailing bytes (< 8) were not encrypted during write,
        // so they don't need decryption
    }
    
    // Then decompress
    if (is_compressed && opts.compressor) {
        auto decompressed = opts.compressor->decompress(result);
        if (!decompressed) {
            return std::unexpected(DecodeError::DecompressFailed);
        }
        result = std::move(*decompressed);
    }
    
    return result;
}

// ============================================================================
// Single Record Decoding
// ============================================================================

std::expected<std::string, DecodeError> LogDecoder::decode(
    std::span<const std::byte> data,
    const Options& opts) {
    
    auto parsed = parse_header(data);
    if (!parsed.valid) {
        return std::unexpected(DecodeError::InvalidHeader);
    }
    
    if (parsed.data_length == 0) {
        return "";
    }
    
    auto record_data = data.subspan(parsed.data_offset, parsed.data_length);
    
    auto processed = process_data(record_data, opts, 
                                   parsed.is_compressed, parsed.is_encrypted);
    if (!processed) {
        return std::unexpected(processed.error());
    }
    
    return std::string(reinterpret_cast<const char*>(processed->data()), 
                       processed->size());
}

// ============================================================================
// Buffer Decoding (Multiple Records)
// ============================================================================

std::vector<std::string> LogDecoder::decode_buffer(
    std::span<const std::byte> data,
    const Options& opts) {
    
    std::vector<std::string> results;
    std::size_t offset = 0;
    
    while (offset < data.size()) {
        auto remaining = data.subspan(offset);
        
        // Find next valid magic
        bool found = false;
        for (std::size_t i = 0; i < remaining.size(); ++i) {
            char magic = static_cast<char>(remaining[i]);
            if (LogMagicNum::is_valid_start(magic)) {
                offset += i;
                found = true;
                break;
            }
        }
        
        if (!found) break;
        
        auto record_span = data.subspan(offset);
        auto parsed = parse_header(record_span);
        
        if (!parsed.valid) {
            offset++;
            continue;
        }
        
        std::size_t record_size = LogHeader::kHeaderSize + parsed.data_length + LogHeader::kTailerSize;
        
        if (offset + record_size > data.size()) {
            break;  // Incomplete record
        }
        
        auto decoded = decode(record_span.subspan(0, record_size), opts);
        if (decoded) {
            results.push_back(std::move(*decoded));
        }
        
        offset += record_size;
    }
    
    return results;
}

// ============================================================================
// Stream Decoding - For streaming compressed/encrypted files
// ============================================================================

std::expected<std::string, DecodeError> LogDecoder::decode_stream(
    std::span<const std::byte> data,
    const Options& opts) {
    
    // BLOCK-INDEPENDENT ENCRYPTION:
    // - Every block stores its own client_pubkey + nonce in header
    // - Each block is decrypted independently (counter resets per block)
    // - This is crash-safe: no need to track counter across blocks
    
    std::vector<std::byte> all_decrypted_data;
    std::ostringstream plain_text;
    std::size_t offset = 0;
    bool has_compressed = false;
    
    while (offset < data.size()) {
        auto remaining = data.subspan(offset);
        
        // Find next valid magic
        bool found = false;
        std::size_t skip_bytes = 0;
        for (std::size_t i = 0; i < remaining.size(); ++i) {
            char magic = static_cast<char>(remaining[i]);
            if (LogMagicNum::is_valid_start(magic)) {
                skip_bytes = i;
                found = true;
                break;
            }
        }
        
        // Copy any plain text before the magic (like startup marker)
        if (skip_bytes > 0) {
            auto plain = remaining.subspan(0, skip_bytes);
            plain_text << std::string_view(
                reinterpret_cast<const char*>(plain.data()), plain.size());
        }
        
        if (!found) break;
        
        offset += skip_bytes;
        auto record_span = data.subspan(offset);
        auto parsed = parse_header(record_span);
        
        if (!parsed.valid) {
            offset++;
            continue;
        }
        
        std::size_t record_size = LogHeader::kHeaderSize + parsed.data_length + LogHeader::kTailerSize;
        
        if (offset + record_size > data.size()) {
            break;  // Incomplete record
        }
        
        // Extract data portion
        auto record_data = record_span.subspan(parsed.data_offset, parsed.data_length);
        
        if (parsed.is_compressed || parsed.is_encrypted) {
            has_compressed = parsed.is_compressed;
            
            // Copy block data for processing
            std::vector<std::byte> block_data(record_data.begin(), record_data.end());
            
            // Decrypt this block independently
            if (parsed.is_encrypted && opts.encryptor) {
                auto header_ptr = record_span.data();
                auto pubkey = LogHeader::get_client_pubkey(header_ptr);
                auto nonce = LogHeader::get_nonce(header_ptr);
                
                // Check if this block has valid pubkey
                bool has_pubkey = false;
                for (auto b : pubkey) {
                    if (std::to_integer<int>(b) != 0) { has_pubkey = true; break; }
                }
                
                if (has_pubkey) {
                    // Reset counter to 0 for this block's decryption
                    opts.encryptor->set_nonce(nonce);
                    
                    // Decrypt each 8-byte chunk with counter starting from 0
                    std::size_t chunk_count = block_data.size() / 8;
                    for (std::size_t i = 0; i < chunk_count; ++i) {
                        auto chunk_span = std::span<std::byte>(block_data.data() + i * 8, 8);
                        auto result = opts.encryptor->decrypt(chunk_span);
                        if (!result) {
                            return std::unexpected(DecodeError::DecryptFailed);
                        }
                        std::memcpy(chunk_span.data(), result->data(), 8);
                    }
                    // Note: trailing bytes (< 8) were not encrypted, leave as-is
                }
            }
            
            // Append decrypted block data
            all_decrypted_data.insert(all_decrypted_data.end(),
                                      block_data.begin(), block_data.end());
        } else {
            // Plain text record
            plain_text << std::string_view(
                reinterpret_cast<const char*>(record_data.data()),
                record_data.size());
        }
        
        offset += record_size;
    }
    
    // Decompress all decrypted data at once (streaming decompression)
    std::string result = plain_text.str();
    if (has_compressed && opts.compressor && !all_decrypted_data.empty()) {
        auto decompressed = opts.compressor->decompress(all_decrypted_data);
        if (!decompressed) {
            return std::unexpected(DecodeError::DecompressFailed);
        }
        result += std::string_view(
            reinterpret_cast<const char*>(decompressed->data()),
            decompressed->size());
    } else if (!all_decrypted_data.empty()) {
        result += std::string_view(
            reinterpret_cast<const char*>(all_decrypted_data.data()),
            all_decrypted_data.size());
    }
    
    return result;
}

// ============================================================================
// File Decoding
// ============================================================================

std::expected<std::string, DecodeError> LogDecoder::decode_file(
    const std::filesystem::path& path,
    const Options& opts) {
    
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return std::unexpected(DecodeError::FileNotFound);
    }
    
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return std::unexpected(DecodeError::OpenFailed);
    }
    
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<std::byte> buffer(static_cast<std::size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return std::unexpected(DecodeError::ReadFailed);
    }
    
    // Use streaming decoder for better handling of streaming compression
    return decode_stream(buffer, opts);
}

std::expected<std::string, DecodeError> LogDecoder::decode_mmap(
    const std::filesystem::path& mmap_path,
    const Options& opts) {
    
    auto buffer_result = MmapBuffer::create(mmap_path);
    if (!buffer_result) {
        return std::unexpected(DecodeError::OpenFailed);
    }
    
    auto& mmap = *buffer_result;
    auto recovered = mmap->recover();
    
    if (recovered.empty()) {
        return "";
    }
    
    std::span<const std::byte> data{
        reinterpret_cast<const std::byte*>(recovered.data()),
        recovered.size()
    };
    
    return decode(data, opts);
}

// ============================================================================
// Hex Dump - Delegate to utils
// ============================================================================

std::string LogDecoder::hex_dump(const void* data, std::size_t len, 
                                  std::size_t bytes_per_line) {
    return logln::hex_dump(data, len, bytes_per_line);
}

std::string LogDecoder::dump_with_header(const void* data, std::size_t len) {
    return logln::dump_with_header(data, len);
}

} // namespace logln

// ============================================================================
// C API Implementation
// ============================================================================

struct logln_decoder_impl {
    std::unique_ptr<logln::ZstdCompressor> compressor;
    std::unique_ptr<logln::IEncryptor> encryptor;
    std::string private_key_hex;  // Store private key for deferred decryptor creation
    
    logln::LogDecoder::Options get_options() const {
        return {
            .compressor = compressor.get(),
            .encryptor = encryptor.get()
        };
    }
};

extern "C" {

LOGLN_DECODER_API logln_decoder_t logln_decoder_create(void) {
    try {
        return new logln_decoder_impl{};
    } catch (...) {
        return nullptr;
    }
}

LOGLN_DECODER_API void logln_decoder_destroy(logln_decoder_t decoder) {
    delete decoder;
}

LOGLN_DECODER_API int logln_decoder_enable_decompression(logln_decoder_t decoder) {
    if (!decoder) return LOGLN_DECODE_NULL_PARAM;
    try {
        decoder->compressor = std::make_unique<logln::ZstdCompressor>();
        return LOGLN_DECODE_OK;
    } catch (...) {
        return LOGLN_DECODE_ALLOC_FAILED;
    }
}

LOGLN_DECODER_API int logln_decoder_disable_decompression(logln_decoder_t decoder) {
    if (!decoder) return LOGLN_DECODE_NULL_PARAM;
    decoder->compressor.reset();
    return LOGLN_DECODE_OK;
}

LOGLN_DECODER_API int logln_decoder_set_private_key(
    logln_decoder_t decoder,
    const uint8_t* private_key,
    size_t key_len) {
    if (!decoder || !private_key) return LOGLN_DECODE_NULL_PARAM;
    if (key_len != 32) return LOGLN_DECODE_INVALID_DATA;
    
    try {
        // Convert bytes to hex string and store for later use
        std::string hex_key;
        hex_key.reserve(64);
        for (size_t i = 0; i < key_len; ++i) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", private_key[i]);
            hex_key += buf;
        }
        decoder->private_key_hex = std::move(hex_key);
        return LOGLN_DECODE_OK;
    } catch (...) {
        return LOGLN_DECODE_ALLOC_FAILED;
    }
}

LOGLN_DECODER_API int logln_decoder_clear_key(logln_decoder_t decoder) {
    if (!decoder) return LOGLN_DECODE_NULL_PARAM;
    decoder->encryptor.reset();
    decoder->private_key_hex.clear();
    return LOGLN_DECODE_OK;
}

static int decode_error_to_c(logln::DecodeError err) {
    switch (err) {
        case logln::DecodeError::None: return LOGLN_DECODE_OK;
        case logln::DecodeError::InvalidData: return LOGLN_DECODE_INVALID_DATA;
        case logln::DecodeError::InvalidHeader: return LOGLN_DECODE_INVALID_HEADER;
        case logln::DecodeError::FileNotFound: return LOGLN_DECODE_FILE_NOT_FOUND;
        case logln::DecodeError::OpenFailed: return LOGLN_DECODE_OPEN_FAILED;
        case logln::DecodeError::ReadFailed: return LOGLN_DECODE_READ_FAILED;
        case logln::DecodeError::DecompressFailed: return LOGLN_DECODE_DECOMPRESS_FAIL;
        case logln::DecodeError::DecryptFailed: return LOGLN_DECODE_DECRYPT_FAIL;
    }
    return LOGLN_DECODE_INVALID_DATA;
}

static int alloc_output(const std::string& str, char** output, size_t* output_len) {
    if (!output) return LOGLN_DECODE_NULL_PARAM;
    
    *output = static_cast<char*>(std::malloc(str.size() + 1));
    if (!*output) return LOGLN_DECODE_ALLOC_FAILED;
    
    std::memcpy(*output, str.data(), str.size());
    (*output)[str.size()] = '\0';
    
    if (output_len) *output_len = str.size();
    return LOGLN_DECODE_OK;
}

LOGLN_DECODER_API int logln_decoder_decode_file(
    logln_decoder_t decoder,
    const char* file_path,
    char** output,
    size_t* output_len) {
    
    if (!decoder || !file_path || !output) return LOGLN_DECODE_NULL_PARAM;
    
    try {
        // If private key is set, read client pubkey from file and create decryptor
        if (!decoder->private_key_hex.empty()) {
            std::vector<std::byte> pubkey(64);
            FILE* fp = std::fopen(file_path, "rb");
            if (!fp) return LOGLN_DECODE_OPEN_FAILED;
            
            // Skip magic(1)+seq(2)+hours(2)+length(4) = 9 bytes to get to pubkey
            std::fseek(fp, 9, SEEK_SET);
            size_t read = std::fread(pubkey.data(), 1, 64, fp);
            std::fclose(fp);
            
            if (read != 64) return LOGLN_DECODE_READ_FAILED;
            
            // Check if pubkey is valid (not all zeros)
            bool has_pubkey = false;
            for (auto b : pubkey) {
                if (std::to_integer<int>(b) != 0) { has_pubkey = true; break; }
            }
            
            if (has_pubkey) {
                decoder->encryptor = logln::create_decryptor(pubkey, decoder->private_key_hex);
            }
        }
        
        auto result = logln::LogDecoder::decode_file(file_path, decoder->get_options());
        if (!result) {
            return decode_error_to_c(result.error());
        }
        return alloc_output(*result, output, output_len);
    } catch (...) {
        return LOGLN_DECODE_READ_FAILED;
    }
}

LOGLN_DECODER_API int logln_decoder_decode_mmap(
    logln_decoder_t decoder,
    const char* file_path,
    char** output,
    size_t* output_len) {
    
    if (!decoder || !file_path || !output) return LOGLN_DECODE_NULL_PARAM;
    
    try {
        // If private key is set, read client pubkey from file and create decryptor
        if (!decoder->private_key_hex.empty()) {
            std::vector<std::byte> pubkey(64);
            FILE* fp = std::fopen(file_path, "rb");
            if (!fp) return LOGLN_DECODE_OPEN_FAILED;
            
            // Skip magic(1)+seq(2)+hours(2)+length(4) = 9 bytes to get to pubkey
            std::fseek(fp, 9, SEEK_SET);
            size_t read = std::fread(pubkey.data(), 1, 64, fp);
            std::fclose(fp);
            
            if (read != 64) return LOGLN_DECODE_READ_FAILED;
            
            // Check if pubkey is valid (not all zeros)
            bool has_pubkey = false;
            for (auto b : pubkey) {
                if (std::to_integer<int>(b) != 0) { has_pubkey = true; break; }
            }
            
            if (has_pubkey) {
                decoder->encryptor = logln::create_decryptor(pubkey, decoder->private_key_hex);
            }
        }
        
        auto result = logln::LogDecoder::decode_mmap(file_path, decoder->get_options());
        if (!result) {
            return decode_error_to_c(result.error());
        }
        return alloc_output(*result, output, output_len);
    } catch (...) {
        return LOGLN_DECODE_READ_FAILED;
    }
}

LOGLN_DECODER_API int logln_decoder_decode_buffer(
    logln_decoder_t decoder,
    const uint8_t* data,
    size_t data_len,
    char** output,
    size_t* output_len) {
    
    if (!decoder || !data || !output) return LOGLN_DECODE_NULL_PARAM;
    
    try {
        std::span<const std::byte> span{
            reinterpret_cast<const std::byte*>(data), data_len
        };
        auto results = logln::LogDecoder::decode_buffer(span, decoder->get_options());
        
        std::string combined;
        for (const auto& s : results) {
            combined += s;
        }
        return alloc_output(combined, output, output_len);
    } catch (...) {
        return LOGLN_DECODE_READ_FAILED;
    }
}

LOGLN_DECODER_API int logln_decoder_decode_stream(
    logln_decoder_t decoder,
    const uint8_t* data,
    size_t data_len,
    char** output,
    size_t* output_len) {
    
    if (!decoder || !data || !output) return LOGLN_DECODE_NULL_PARAM;
    
    try {
        std::span<const std::byte> span{
            reinterpret_cast<const std::byte*>(data), data_len
        };
        auto result = logln::LogDecoder::decode_stream(span, decoder->get_options());
        if (!result) {
            return decode_error_to_c(result.error());
        }
        return alloc_output(*result, output, output_len);
    } catch (...) {
        return LOGLN_DECODE_READ_FAILED;
    }
}

LOGLN_DECODER_API void logln_decoder_free_string(char* str) {
    std::free(str);
}

LOGLN_DECODER_API const char* logln_decoder_error_string(int error) {
    switch (error) {
        case LOGLN_DECODE_OK: return "Success";
        case LOGLN_DECODE_INVALID_DATA: return "Invalid input data";
        case LOGLN_DECODE_INVALID_HEADER: return "Invalid log header";
        case LOGLN_DECODE_FILE_NOT_FOUND: return "File not found";
        case LOGLN_DECODE_OPEN_FAILED: return "Failed to open file";
        case LOGLN_DECODE_READ_FAILED: return "Failed to read file";
        case LOGLN_DECODE_DECOMPRESS_FAIL: return "Decompression failed";
        case LOGLN_DECODE_DECRYPT_FAIL: return "Decryption failed";
        case LOGLN_DECODE_NULL_PARAM: return "Null parameter provided";
        case LOGLN_DECODE_ALLOC_FAILED: return "Memory allocation failed";
        default: return "Unknown error";
    }
}

LOGLN_DECODER_API const char* logln_decoder_version(void) {
    return "1.0.0";
}

} // extern "C"
