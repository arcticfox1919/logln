// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors
//
// loglnd - High-performance log decoder tool
//
// Decodes .blog (binary log) and .mmap (crash recovery) files to readable .log format.
//
// Usage:
//   loglnd <file.blog|file.mmap> [output.log]
//   loglnd <directory>
//   loglnd --private-key <hex> <file.blog>  (for encrypted logs)

#include <logln/decoder.h>

// Internal headers for compression/encryption support
#include "compressor.hpp"
#include "encryptor.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace logln;

// ============================================================================
// Global Options
// ============================================================================

static std::unique_ptr<ZstdCompressor> g_compressor;
static std::string g_server_priv_key_hex;
static std::unique_ptr<IEncryptor> g_encryptor;

// Read client public key from file header (bytes 9-72, 64 bytes)
static std::vector<std::byte> read_client_pubkey(const fs::path& path) {
    std::vector<std::byte> pubkey(64);
    FILE* fp = std::fopen(path.string().c_str(), "rb");
    if (!fp) return {};
    
    // Seek to byte 9 (after magic, seq, begin_hour, end_hour, length)
    if (std::fseek(fp, 9, SEEK_SET) != 0) {
        std::fclose(fp);
        return {};
    }
    
    if (std::fread(pubkey.data(), 1, 64, fp) != 64) {
        std::fclose(fp);
        return {};
    }
    
    std::fclose(fp);
    return pubkey;
}

// Read nonce from file header (bytes 73-88, 16 bytes)
static std::vector<std::byte> read_nonce(const fs::path& path) {
    std::vector<std::byte> nonce(16);
    FILE* fp = std::fopen(path.string().c_str(), "rb");
    if (!fp) return {};
    
    // Seek to byte 73 (after magic, seq, hours, length, client_pubkey)
    if (std::fseek(fp, 73, SEEK_SET) != 0) {
        std::fclose(fp);
        return {};
    }
    
    if (std::fread(nonce.data(), 1, 16, fp) != 16) {
        std::fclose(fp);
        return {};
    }
    
    std::fclose(fp);
    return nonce;
}

static LogDecoder::Options make_decoder_opts([[maybe_unused]] const fs::path& input_path) {
    LogDecoder::Options opts{};
    
    // Always enable compressor for decoding
    if (!g_compressor) {
        g_compressor = std::make_unique<ZstdCompressor>();
    }
    opts.compressor = g_compressor.get();
    
    // Setup encryptor if private key provided
    if (!g_server_priv_key_hex.empty()) {
        // Read client public key from file header
        auto client_pubkey = read_client_pubkey(input_path);
        if (!client_pubkey.empty()) {
            g_encryptor = create_decryptor(client_pubkey, g_server_priv_key_hex);
            // Read and set nonce from header
            auto nonce = read_nonce(input_path);
            if (!nonce.empty() && g_encryptor) {
                g_encryptor->set_nonce(nonce);
            }
        }
    }
    if (g_encryptor) {
        opts.encryptor = g_encryptor.get();
    }
    
    return opts;
}

// ============================================================================
// Utilities
// ============================================================================

static void print_usage(const char* prog) {
    std::fprintf(stderr,
        "loglnd - Decode binary log files to readable format\n\n"
        "Usage:\n"
        "  %s <file.blog|file.mmap> [output.log]\n"
        "  %s <directory>\n"
        "  %s --private-key <hex> <file.blog>  (for encrypted logs)\n\n"
        "Options:\n"
        "  --private-key, -k <hex>  Server private key (64 hex chars) for decryption\n"
        "  -r, --recursive          Process directories recursively\n"
        "  -h, --help               Show this help message\n\n"
        "Supported formats:\n"
        "  .blog  Binary log (compressed/encrypted)\n"
        "  .mmap  Memory-mapped buffer (crash recovery)\n\n"
        "Examples:\n"
        "  %s app.blog              # -> app.log\n"
        "  %s crash.mmap            # -> crash.log\n"
        "  %s app.blog out.log      # -> out.log\n"
        "  %s ./logs/               # batch decode directory\n"
        "  %s ./logs/ -r            # recursive batch decode\n"
        "  %s --private-key 0123...abcd secret.blog  # decrypt\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

static std::string make_output_path(const fs::path& input) {
    std::string stem = input.stem().string();
    fs::path dir = input.parent_path();
    if (dir.empty()) dir = ".";
    
    return (dir / (stem + ".log")).string();
}

static bool decode_single_file(const fs::path& input, const fs::path& output) {
    auto opts = make_decoder_opts(input);
    auto result = (input.extension() == ".mmap")
        ? LogDecoder::decode_mmap(input, opts)
        : LogDecoder::decode_file(input, opts);
    
    if (!result) {
        const char* err = "unknown error";
        switch (result.error()) {
            case DecodeError::FileNotFound:     err = "file not found"; break;
            case DecodeError::OpenFailed:       err = "open failed"; break;
            case DecodeError::ReadFailed:       err = "read failed"; break;
            case DecodeError::InvalidHeader:    err = "invalid header"; break;
            case DecodeError::InvalidData:      err = "corrupted data"; break;
            case DecodeError::DecompressFailed: err = "decompress failed"; break;
            case DecodeError::DecryptFailed:    err = "decrypt failed"; break;
            default: break;
        }
        std::fprintf(stderr, "[ERROR] %s: %s\n", 
            input.filename().string().c_str(), err);
        return false;
    }
    
    const auto& content = result.value();
    if (content.empty()) {
        std::fprintf(stderr, "[SKIP] %s: empty\n", 
            input.filename().string().c_str());
        return true;
    }
    
    FILE* fp = std::fopen(output.string().c_str(), "wb");
    if (!fp) {
        std::fprintf(stderr, "[ERROR] %s: cannot create output\n", 
            output.filename().string().c_str());
        return false;
    }
    
    std::fwrite(content.data(), 1, content.size(), fp);
    std::fclose(fp);
    
    std::printf("[OK] %s -> %s (%zu bytes)\n", 
        input.filename().string().c_str(), 
        output.filename().string().c_str(), 
        content.size());
    return true;
}

static int decode_directory(const fs::path& dir, bool recursive = false) {
    std::vector<fs::path> files;
    std::error_code ec;
    
    auto collect_files = [&](const auto& entry) {
        if (!entry.is_regular_file()) return;
        auto ext = entry.path().extension();
        if (ext == ".blog" || ext == ".mmap") {
            files.push_back(entry.path());
        }
    };
    
    if (recursive) {
        for (const auto& entry : fs::recursive_directory_iterator(dir, ec)) {
            collect_files(entry);
        }
    } else {
        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            collect_files(entry);
        }
    }
    
    if (files.empty()) {
        std::fprintf(stderr, "No .blog or .mmap files found in %s\n", 
            dir.string().c_str());
        return 1;
    }
    
    std::printf("Found %zu file(s)\n\n", files.size());
    
    int ok = 0, fail = 0;
    for (const auto& f : files) {
        if (decode_single_file(f, make_output_path(f))) {
            ++ok;
        } else {
            ++fail;
        }
    }
    
    std::printf("\nDecoded: %d, Failed: %d\n", ok, fail);
    return fail > 0 ? 1 : 0;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    int arg_idx = 1;
    bool recursive = false;
    
    // Parse options
    while (arg_idx < argc) {
        const char* arg = argv[arg_idx];
        
        if (std::strcmp(arg, "-h") == 0 || std::strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        
        if (std::strcmp(arg, "-r") == 0 || std::strcmp(arg, "--recursive") == 0) {
            recursive = true;
            ++arg_idx;
            continue;
        }
        
        if (std::strcmp(arg, "--private-key") == 0 || std::strcmp(arg, "-k") == 0) {
            if (arg_idx + 1 >= argc) {
                std::fprintf(stderr, "Missing value for %s\n", arg);
                return 1;
            }
            g_server_priv_key_hex = argv[arg_idx + 1];
            if (g_server_priv_key_hex.length() != 64) {
                std::fprintf(stderr, "Private key must be 64 hex characters (32 bytes)\n");
                return 1;
            }
            arg_idx += 2;
            continue;
        }
        
        // Not an option, must be input path
        break;
    }
    
    if (arg_idx >= argc) {
        std::fprintf(stderr, "Missing input file or directory\n");
        print_usage(argv[0]);
        return 1;
    }
    
    fs::path input(argv[arg_idx]);
    std::error_code ec;
    
    // Directory mode
    if (fs::is_directory(input, ec)) {
        return decode_directory(input, recursive);
    }
    
    // Single file mode
    if (!fs::exists(input, ec)) {
        std::fprintf(stderr, "File not found: %s\n", argv[arg_idx]);
        return 1;
    }
    
    auto ext = input.extension();
    if (ext != ".blog" && ext != ".mmap") {
        std::fprintf(stderr, "Unsupported format: %s (expected .blog or .mmap)\n", 
            ext.string().c_str());
        return 1;
    }
    
    fs::path output = (arg_idx + 1 < argc) 
        ? fs::path(argv[arg_idx + 1]) 
        : fs::path(make_output_path(input));
    
    return decode_single_file(input, output) ? 0 : 1;
}
