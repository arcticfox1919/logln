// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

/**
 * @file decoder.h
 * @brief Logln Decoder - Decode compressed/encrypted log files
 * 
 * This header provides both C and C++ APIs for decoding log files created by Logln.
 * The C API is designed for cross-language FFI bindings (Java/JNI, Swift, Python, Rust, etc.)
 * 
 * C Usage:
 * @code
 * logln_decoder_t decoder = logln_decoder_create();
 * logln_decoder_enable_decompression(decoder);
 * 
 * char* output = NULL;
 * size_t output_len = 0;
 * if (logln_decoder_decode_file(decoder, "app.blog", &output, &output_len) == LOGLN_DECODE_OK) {
 *     printf("%s", output);
 *     logln_decoder_free_string(output);
 * }
 * logln_decoder_destroy(decoder);
 * @endcode
 */

#ifndef LOGLN_DECODER_H
#define LOGLN_DECODER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ============================================================================
// Export Macros
// ============================================================================

#if defined(_WIN32) || defined(_WIN64)
    #ifdef LOGLN_DECODER_BUILDING_DLL
        #define LOGLN_DECODER_API __declspec(dllexport)
    #elif defined(LOGLN_DECODER_USING_DLL)
        #define LOGLN_DECODER_API __declspec(dllimport)
    #else
        #define LOGLN_DECODER_API
    #endif
#else
    #if __GNUC__ >= 4 || defined(__clang__)
        #define LOGLN_DECODER_API __attribute__((visibility("default")))
    #else
        #define LOGLN_DECODER_API
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// C API - Error Codes
// ============================================================================

typedef enum logln_decode_error {
    LOGLN_DECODE_OK              = 0,   /**< Success */
    LOGLN_DECODE_INVALID_DATA    = 1,   /**< Invalid input data */
    LOGLN_DECODE_INVALID_HEADER  = 2,   /**< Invalid log header */
    LOGLN_DECODE_FILE_NOT_FOUND  = 3,   /**< File not found */
    LOGLN_DECODE_OPEN_FAILED     = 4,   /**< Failed to open file */
    LOGLN_DECODE_READ_FAILED     = 5,   /**< Failed to read file */
    LOGLN_DECODE_DECOMPRESS_FAIL = 6,   /**< Decompression failed */
    LOGLN_DECODE_DECRYPT_FAIL    = 7,   /**< Decryption failed */
    LOGLN_DECODE_NULL_PARAM      = 8,   /**< Null parameter provided */
    LOGLN_DECODE_ALLOC_FAILED    = 9,   /**< Memory allocation failed */
} logln_decode_error_t;

// ============================================================================
// C API - Opaque Handle
// ============================================================================

typedef struct logln_decoder_impl* logln_decoder_t;

// ============================================================================
// C API - Decoder Lifecycle
// ============================================================================

LOGLN_DECODER_API logln_decoder_t logln_decoder_create(void);
LOGLN_DECODER_API void logln_decoder_destroy(logln_decoder_t decoder);

// ============================================================================
// C API - Configuration
// ============================================================================

LOGLN_DECODER_API int logln_decoder_enable_decompression(logln_decoder_t decoder);
LOGLN_DECODER_API int logln_decoder_disable_decompression(logln_decoder_t decoder);

/**
 * @brief Set private key for decryption (ECDH + ChaCha20)
 * @param decoder Decoder handle
 * @param private_key Private key bytes (32 bytes for secp256k1)
 * @param key_len Length of private key
 */
LOGLN_DECODER_API int logln_decoder_set_private_key(
    logln_decoder_t decoder,
    const uint8_t* private_key,
    size_t key_len);

LOGLN_DECODER_API int logln_decoder_clear_key(logln_decoder_t decoder);

// ============================================================================
// C API - Decoding Functions
// ============================================================================

/**
 * @brief Decode a log file (.blog)
 * @param decoder Decoder handle
 * @param file_path Path to the log file (UTF-8)
 * @param[out] output Pointer to receive decoded string (caller must free with logln_decoder_free_string)
 * @param[out] output_len Length of decoded string (excluding null terminator)
 */
LOGLN_DECODER_API int logln_decoder_decode_file(
    logln_decoder_t decoder,
    const char* file_path,
    char** output,
    size_t* output_len);

/**
 * @brief Decode an mmap buffer file (for crash recovery)
 */
LOGLN_DECODER_API int logln_decoder_decode_mmap(
    logln_decoder_t decoder,
    const char* file_path,
    char** output,
    size_t* output_len);

/**
 * @brief Decode raw buffer data
 */
LOGLN_DECODER_API int logln_decoder_decode_buffer(
    logln_decoder_t decoder,
    const uint8_t* data,
    size_t data_len,
    char** output,
    size_t* output_len);

/**
 * @brief Decode streaming compressed data
 */
LOGLN_DECODER_API int logln_decoder_decode_stream(
    logln_decoder_t decoder,
    const uint8_t* data,
    size_t data_len,
    char** output,
    size_t* output_len);

// ============================================================================
// C API - Memory Management
// ============================================================================

LOGLN_DECODER_API void logln_decoder_free_string(char* str);

// ============================================================================
// C API - Utilities
// ============================================================================

LOGLN_DECODER_API const char* logln_decoder_error_string(int error);
LOGLN_DECODER_API const char* logln_decoder_version(void);

#ifdef __cplusplus
}
#endif

// ============================================================================
// C++ API
// ============================================================================

#ifdef __cplusplus

#include <cstddef>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace logln {

// Forward declarations
class ICompressor;
class IEncryptor;

// ============================================================================
// Decoder Error Types
// ============================================================================

enum class DecodeError {
    None = 0,
    InvalidData,
    InvalidHeader,
    FileNotFound,
    OpenFailed,
    ReadFailed,
    DecompressFailed,
    DecryptFailed,
};

// ============================================================================
// LogDecoder - C++ API for decoding log data
// ============================================================================

class LogDecoder {
public:
    struct Options {
        ICompressor* compressor = nullptr;
        IEncryptor* encryptor = nullptr;
    };
    
    // ========================================================================
    // Single Record Decoding
    // ========================================================================
    
    [[nodiscard]] static std::expected<std::string, DecodeError> decode(
        std::span<const std::byte> data,
        const Options& opts);
    
    [[nodiscard]] static std::expected<std::string, DecodeError> decode(
        std::span<const std::byte> data) {
        return decode(data, Options{});
    }
    
    // ========================================================================
    // Buffer Decoding
    // ========================================================================
    
    [[nodiscard]] static std::vector<std::string> decode_buffer(
        std::span<const std::byte> data,
        const Options& opts);
    
    [[nodiscard]] static std::vector<std::string> decode_buffer(
        std::span<const std::byte> data) {
        return decode_buffer(data, Options{});
    }
    
    // ========================================================================
    // Stream Decoding
    // ========================================================================
    
    [[nodiscard]] static std::expected<std::string, DecodeError> decode_stream(
        std::span<const std::byte> data,
        const Options& opts);
    
    // ========================================================================
    // File Decoding  
    // ========================================================================
    
    [[nodiscard]] static std::expected<std::string, DecodeError> decode_file(
        const std::filesystem::path& path,
        const Options& opts);
    
    [[nodiscard]] static std::expected<std::string, DecodeError> decode_file(
        const std::filesystem::path& path) {
        return decode_file(path, Options{});
    }
    
    [[nodiscard]] static std::expected<std::string, DecodeError> decode_mmap(
        const std::filesystem::path& mmap_path,
        const Options& opts);
    
    [[nodiscard]] static std::expected<std::string, DecodeError> decode_mmap(
        const std::filesystem::path& mmap_path) {
        return decode_mmap(mmap_path, Options{});
    }
    
    // ========================================================================
    // Hex Dump (for debugging)
    // ========================================================================
    
    [[nodiscard]] static std::string hex_dump(
        const void* data, 
        std::size_t len,
        std::size_t bytes_per_line = 16);
    
    [[nodiscard]] static std::string dump_with_header(
        const void* data,
        std::size_t len);

private:
    struct ParseResult {
        bool valid = false;
        std::size_t data_offset = 0;
        std::size_t data_length = 0;
        bool is_compressed = false;
        bool is_encrypted = false;
    };
    
    [[nodiscard]] static ParseResult parse_header(
        std::span<const std::byte> data);
    
    [[nodiscard]] static std::expected<std::vector<std::byte>, DecodeError> 
    process_data(std::span<const std::byte> data, const Options& opts,
                 bool is_compressed, bool is_encrypted);
};

} // namespace logln

#endif // __cplusplus

#endif // LOGLN_DECODER_H
