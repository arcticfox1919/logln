// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors
//
// loglnk - Generate secp256k1 key pair for log encryption
//
// Usage:
//   loglnk              # Generate and print key pair
//   loglnk -o keys.txt  # Save to file

#include <cstdio>
#include <cstring>
#include <random>
#include <array>
#include <string>

#include <uECC.h>

// ============================================================================
// Random Number Generator
// ============================================================================

static int rng_function(uint8_t* dest, unsigned size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (unsigned i = 0; i < size; ++i) {
        dest[i] = static_cast<uint8_t>(dis(gen));
    }
    return 1;
}

// ============================================================================
// Hex Conversion
// ============================================================================

static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::string hex;
    hex.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", data[i]);
        hex += buf;
    }
    return hex;
}

// ============================================================================
// Main
// ============================================================================

static void print_usage(const char* prog) {
    std::fprintf(stderr,
        "loglnk - Generate secp256k1 key pair for log encryption\n\n"
        "Usage:\n"
        "  %s              Generate and print key pair\n"
        "  %s -o <file>    Save key pair to file\n"
        "  %s -h           Show this help\n\n"
        "Output format:\n"
        "  Private Key: 64 hex characters (32 bytes)\n"
        "  Public Key:  128 hex characters (64 bytes)\n\n"
        "Example:\n"
        "  %s\n"
        "  %s -o server_keys.txt\n",
        prog, prog, prog, prog, prog);
}

int main(int argc, char* argv[]) {
    FILE* out = stdout;
    const char* out_path = nullptr;
    
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (std::strcmp(argv[i], "-o") == 0 || std::strcmp(argv[i], "--output") == 0) {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Missing output file path\n");
                return 1;
            }
            out_path = argv[++i];
        }
    }
    
    // Set RNG
    uECC_set_rng(rng_function);
    
    // Get curve
    const struct uECC_Curve_t* curve = uECC_secp256k1();
    
    // Generate key pair
    std::array<uint8_t, 64> public_key{};   // Uncompressed: 64 bytes
    std::array<uint8_t, 32> private_key{};  // 32 bytes
    
    if (!uECC_make_key(public_key.data(), private_key.data(), curve)) {
        std::fprintf(stderr, "Failed to generate key pair\n");
        return 1;
    }
    
    // Convert to hex
    std::string priv_hex = bytes_to_hex(private_key.data(), private_key.size());
    std::string pub_hex = bytes_to_hex(public_key.data(), public_key.size());
    
    // Open output file if specified
    if (out_path) {
        out = std::fopen(out_path, "w");
        if (!out) {
            std::fprintf(stderr, "Cannot open output file: %s\n", out_path);
            return 1;
        }
    }
    
    // Print results
    std::fprintf(out, "# Logln Encryption Key Pair (secp256k1)\n");
    std::fprintf(out, "# Generated for use with logln log encryption\n");
    std::fprintf(out, "#\n");
    std::fprintf(out, "# KEEP THE PRIVATE KEY SECRET!\n");
    std::fprintf(out, "# Only share the public key.\n");
    std::fprintf(out, "#\n");
    std::fprintf(out, "# Usage:\n");
    std::fprintf(out, "#   App config:  config.pub_key = \"<PUBLIC_KEY>\"\n");
    std::fprintf(out, "#   Decryption:  loglnd --private-key <PRIVATE_KEY> encrypted.blog\n");
    std::fprintf(out, "\n");
    std::fprintf(out, "PRIVATE_KEY=%s\n", priv_hex.c_str());
    std::fprintf(out, "PUBLIC_KEY=%s\n", pub_hex.c_str());
    
    // Also print to stderr if writing to file (so user sees the output)
    if (out_path) {
        std::fclose(out);
        std::fprintf(stderr, "Key pair saved to: %s\n\n", out_path);
        std::fprintf(stderr, "Public Key (for app config):\n%s\n\n", pub_hex.c_str());
        std::fprintf(stderr, "Private Key (KEEP SECRET, for decryption):\n%s\n", priv_hex.c_str());
    }
    
    // Secure wipe private key from memory
    std::memset(private_key.data(), 0, private_key.size());
    
    return 0;
}
