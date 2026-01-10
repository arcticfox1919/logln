// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors
//
// Encryption Integration Tests - Tests complete Logger compress+encrypt write and Decoder decrypt+decompress flow
//
// This is the most critical test: verify that encrypted logs written by Logger can be correctly decrypted by Decoder

#include <gtest/gtest.h>
#include <logln/logln.h>
#include <logln/decoder.h>
#include "compressor.hpp"
#include "encryptor.hpp"

#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;
using namespace std::chrono_literals;

// Test key pair (same as examples/advanced.cpp)
constexpr const char* SERVER_PRIVATE_KEY = "af3cd491a07442a660ac6ce5884ece8baa52e5437afa2ca7e9cb5589e0fe7e25";
constexpr const char* SERVER_PUBLIC_KEY  = "948f2886d96eceef15f56f03ad8d99c74bcaa6cfa753c2db684574e38e7f4440497c6ae54586115a6f4eb7f65679064b72e6752a3a287d39a694d751d7b94d94";

class EncryptionIntegrationTest : public ::testing::Test {
protected:
    fs::path test_log_dir_;
    
    void SetUp() override {
        // Create temporary test directory
        test_log_dir_ = fs::temp_directory_path() / "logln_encryption_test";
        fs::remove_all(test_log_dir_);
        fs::create_directories(test_log_dir_);
    }
    
    void TearDown() override {
        // Release all loggers first
        logln::Logger::release_all();
        
        // Clean up test directory
        std::error_code ec;
        fs::remove_all(test_log_dir_, ec);
    }
    
    // Get .blog files in test directory
    std::vector<fs::path> get_blog_files() {
        std::vector<fs::path> files;
        for (const auto& entry : fs::directory_iterator(test_log_dir_)) {
            if (entry.path().extension() == ".blog") {
                files.push_back(entry.path());
            }
        }
        return files;
    }
    
    // Decode file using C++ API
    std::string decode_file_cpp(const fs::path& path, bool use_compression, bool use_encryption) {
        logln::LogDecoder::Options opts;
        std::unique_ptr<logln::ZstdCompressor> compressor;
        std::unique_ptr<logln::IEncryptor> encryptor;
        
        if (use_compression) {
            compressor = std::make_unique<logln::ZstdCompressor>();
            opts.compressor = compressor.get();
        }
        
        if (use_encryption) {
            // Read client pubkey from file header (bytes 9-72)
            std::vector<std::byte> pubkey(64);
            FILE* fp = std::fopen(path.string().c_str(), "rb");
            if (fp) {
                std::fseek(fp, 9, SEEK_SET);  // Skip magic(1)+seq(2)+hours(2)+length(4)
                std::fread(pubkey.data(), 1, 64, fp);
                std::fclose(fp);
                
                // Create decryptor with client pubkey and server private key
                encryptor = logln::create_decryptor(pubkey, SERVER_PRIVATE_KEY);
            }
        }
        if (encryptor) {
            opts.encryptor = encryptor.get();
        }
        
        auto result = logln::LogDecoder::decode_file(path, opts);
        if (!result) {
            return "DECODE_ERROR: " + std::to_string(static_cast<int>(result.error()));
        }
        return *result;
    }
    
    // Decode file using C API
    std::string decode_file_c(const fs::path& path, bool use_compression, bool use_encryption) {
        logln_decoder_t decoder = logln_decoder_create();
        if (!decoder) {
            return "C_API_ERROR: create failed";
        }
        
        if (use_compression) {
            logln_decoder_enable_decompression(decoder);
        }
        
        if (use_encryption) {
            // Convert hex string to byte array
            uint8_t private_key[32];
            for (int i = 0; i < 32; ++i) {
                unsigned int byte;
                sscanf(SERVER_PRIVATE_KEY + i * 2, "%02x", &byte);
                private_key[i] = static_cast<uint8_t>(byte);
            }
            logln_decoder_set_private_key(decoder, private_key, 32);
        }
        
        char* output = nullptr;
        size_t output_len = 0;
        int result = logln_decoder_decode_file(decoder, path.string().c_str(), &output, &output_len);
        
        std::string decoded;
        if (result == LOGLN_DECODE_OK && output) {
            decoded = std::string(output, output_len);
            logln_decoder_free_string(output);
        } else {
            decoded = "C_API_ERROR: " + std::to_string(result);
        }
        
        logln_decoder_destroy(decoder);
        return decoded;
    }
};

// ============================================================================
// Test 1: Compression Only - Baseline Test
// ============================================================================
TEST_F(EncryptionIntegrationTest, CompressionOnly) {
    std::cout << "\n=== Test 1: Compression Only ===\n";
    
    // Configure Logger: enable compression, no encryption
    auto config = logln::ConfigBuilder()
        .log_dir(test_log_dir_)
        .name("compress_test")
        .level(logln::Level::Debug)
        .zstd(3)
        .console(false)
        .flush_interval(100ms)
        .build();
    
    ASSERT_TRUE(config.has_value()) << "Config should be valid";
    
    auto* logger = logln::Logger::create(*config);
    ASSERT_NE(logger, nullptr) << "Logger should be created";
    
    // Write log messages
    const char* test_messages[] = {
        "Compression test message 1",
        "Compression test message 2",
        "Compression test message 3"
    };
    
    for (const auto* msg : test_messages) {
        logger->info("TestTag", "{}", msg);
    }
    
    // Force flush and release
    logger->flush();
    std::this_thread::sleep_for(200ms);
    logln::Logger::release_all();
    std::this_thread::sleep_for(100ms);
    
    // Find log files
    auto files = get_blog_files();
    ASSERT_FALSE(files.empty()) << "Should have created at least one .blog file";
    
    std::cout << "Created file: " << files[0] << std::endl;
    std::cout << "File size: " << fs::file_size(files[0]) << " bytes" << std::endl;
    
    // Decode
    std::string decoded = decode_file_cpp(files[0], true, false);
    std::cout << "Decoded content length: " << decoded.length() << std::endl;
    std::cout << "Decoded content:\n" << decoded << std::endl;
    
    // Verify
    EXPECT_FALSE(decoded.starts_with("DECODE_ERROR")) << "Decoding should succeed";
    for (const auto* msg : test_messages) {
        EXPECT_TRUE(decoded.find(msg) != std::string::npos) 
            << "Should contain: " << msg;
    }
}

// ============================================================================
// Test 2: Compression + Encryption - Key Test
// ============================================================================
TEST_F(EncryptionIntegrationTest, CompressionAndEncryption) {
    std::cout << "\n=== Test 2: Compression + Encryption ===\n";
    
    // Configure Logger: enable compression and encryption
    auto config = logln::ConfigBuilder()
        .log_dir(test_log_dir_)
        .name("encrypt_test")
        .level(logln::Level::Debug)
        .zstd(3)
        .encrypt(SERVER_PUBLIC_KEY)
        .console(false)
        .flush_interval(100ms)
        .build();
    
    ASSERT_TRUE(config.has_value()) << "Config should be valid";
    
    auto* logger = logln::Logger::create(*config);
    ASSERT_NE(logger, nullptr) << "Logger should be created";
    
    // Write log messages
    const char* test_messages[] = {
        "Encrypted message 1",
        "Encrypted message 2",
        "Encrypted message 3"
    };
    
    for (const auto* msg : test_messages) {
        logger->info("TestTag", "{}", msg);
    }
    
    // Force flush and release
    logger->flush();
    std::this_thread::sleep_for(200ms);
    logln::Logger::release_all();
    std::this_thread::sleep_for(100ms);
    
    // Find log files
    auto files = get_blog_files();
    ASSERT_FALSE(files.empty()) << "Should have created at least one .blog file";
    
    std::cout << "Created file: " << files[0] << std::endl;
    std::cout << "File size: " << fs::file_size(files[0]) << " bytes" << std::endl;
    
    // Decode - using correct private key
    std::string decoded = decode_file_cpp(files[0], true, true);
    std::cout << "Decoded content length: " << decoded.length() << std::endl;
    std::cout << "Decoded content:\n" << decoded << std::endl;
    
    // Verify
    EXPECT_FALSE(decoded.starts_with("DECODE_ERROR")) << "Decoding should succeed";
    for (const auto* msg : test_messages) {
        EXPECT_TRUE(decoded.find(msg) != std::string::npos) 
            << "Should contain: " << msg;
    }
}

// ============================================================================
// Test 3: Compression + Encryption - Multiple Logs (Multi Block)
// ============================================================================
TEST_F(EncryptionIntegrationTest, CompressionAndEncryptionMultiBlock) {
    std::cout << "\n=== Test 3: Compression + Encryption (Multi Block) ===\n";
    
    auto config = logln::ConfigBuilder()
        .log_dir(test_log_dir_)
        .name("multiblock_test")
        .level(logln::Level::Debug)
        .zstd(3)
        .encrypt(SERVER_PUBLIC_KEY)
        .console(false)
        .flush_interval(100ms)
        .build();
    
    ASSERT_TRUE(config.has_value());
    
    auto* logger = logln::Logger::create(*config);
    ASSERT_NE(logger, nullptr);
    
    // Write many logs to generate multiple blocks
    std::vector<std::string> messages;
    for (int i = 0; i < 50; ++i) {
        std::string msg = "Multi-block test message number " + std::to_string(i) + 
                          " with some extra padding to make it longer";
        messages.push_back(msg);
        logger->info("MultiBlock", "{}", msg);
    }
    
    logger->flush();
    std::this_thread::sleep_for(200ms);
    logln::Logger::release_all();
    std::this_thread::sleep_for(100ms);
    
    auto files = get_blog_files();
    ASSERT_FALSE(files.empty());
    
    std::cout << "Created file: " << files[0] << std::endl;
    std::cout << "File size: " << fs::file_size(files[0]) << " bytes" << std::endl;
    
    std::string decoded = decode_file_cpp(files[0], true, true);
    std::cout << "Decoded content length: " << decoded.length() << std::endl;
    
    EXPECT_FALSE(decoded.starts_with("DECODE_ERROR")) << "Decoding should succeed";
    
    // Verify first and last messages all exist
    EXPECT_TRUE(decoded.find("number 0") != std::string::npos);
    EXPECT_TRUE(decoded.find("number 25") != std::string::npos);
    EXPECT_TRUE(decoded.find("number 49") != std::string::npos);
}

// ============================================================================
// Test 4: C API Decoding Test
// ============================================================================
TEST_F(EncryptionIntegrationTest, CApiDecoding) {
    std::cout << "\n=== Test 4: C API Decoding ===\n";
    
    auto config = logln::ConfigBuilder()
        .log_dir(test_log_dir_)
        .name("capi_test")
        .level(logln::Level::Debug)
        .zstd(3)
        .encrypt(SERVER_PUBLIC_KEY)
        .console(false)
        .flush_interval(100ms)
        .build();
    
    ASSERT_TRUE(config.has_value());
    
    auto* logger = logln::Logger::create(*config);
    ASSERT_NE(logger, nullptr);
    
    logger->info("CApi", "C API test message 1");
    logger->info("CApi", "C API test message 2");
    
    logger->flush();
    std::this_thread::sleep_for(200ms);
    logln::Logger::release_all();
    std::this_thread::sleep_for(100ms);
    
    auto files = get_blog_files();
    ASSERT_FALSE(files.empty());
    
    // Decode using C API
    std::string decoded = decode_file_c(files[0], true, true);
    std::cout << "Decoded via C API:\n" << decoded << std::endl;
    
    EXPECT_FALSE(decoded.starts_with("C_API_ERROR")) << "C API decoding should succeed";
    EXPECT_TRUE(decoded.find("C API test message 1") != std::string::npos);
    EXPECT_TRUE(decoded.find("C API test message 2") != std::string::npos);
}

// ============================================================================
// Test 5: Wrong Private Key Should Fail to Decrypt
// ============================================================================
TEST_F(EncryptionIntegrationTest, WrongPrivateKeyShouldFail) {
    std::cout << "\n=== Test 5: Wrong Private Key Should Fail ===\n";
    
    auto config = logln::ConfigBuilder()
        .log_dir(test_log_dir_)
        .name("wrongkey_test")
        .level(logln::Level::Debug)
        .zstd(3)
        .encrypt(SERVER_PUBLIC_KEY)
        .console(false)
        .flush_interval(100ms)
        .build();
    
    ASSERT_TRUE(config.has_value());
    
    auto* logger = logln::Logger::create(*config);
    ASSERT_NE(logger, nullptr);
    
    logger->info("WrongKey", "This should not be readable with wrong key");
    
    logger->flush();
    std::this_thread::sleep_for(200ms);
    logln::Logger::release_all();
    std::this_thread::sleep_for(100ms);
    
    auto files = get_blog_files();
    ASSERT_FALSE(files.empty());
    
    // Try to decode with wrong private key
    const char* WRONG_PRIVATE_KEY = "0000000000000000000000000000000000000000000000000000000000000001";
    
    logln::LogDecoder::Options opts;
    auto compressor = std::make_unique<logln::ZstdCompressor>();
    auto wrong_encryptor = std::make_unique<logln::ChaCha20Encryptor>(WRONG_PRIVATE_KEY);
    opts.compressor = compressor.get();
    opts.encryptor = wrong_encryptor.get();
    
    auto result = logln::LogDecoder::decode_file(files[0], opts);
    
    // Decryption should fail or produce garbage (ZSTD decompression fails)
    if (result) {
        std::cout << "Decoded with wrong key (should be garbage): " << result->substr(0, 100) << std::endl;
        // Even if no error, content should be garbage and should not contain original message
        EXPECT_TRUE(result->find("should not be readable") == std::string::npos) 
            << "Wrong key should not decrypt correctly";
    } else {
        std::cout << "Decoding with wrong key failed as expected: " 
                  << static_cast<int>(result.error()) << std::endl;
        SUCCEED() << "Decoding should fail with wrong key";
    }
}

// ============================================================================
// Test 6: Unencrypted Log Should Not Require Decryptor
// ============================================================================
TEST_F(EncryptionIntegrationTest, UnencryptedLogWithDecryptor) {
    std::cout << "\n=== Test 6: Unencrypted Log With Decryptor ===\n";
    
    // Create unencrypted log
    auto config = logln::ConfigBuilder()
        .log_dir(test_log_dir_)
        .name("unencrypted_test")
        .level(logln::Level::Debug)
        .zstd(3)
        // No encryption
        .console(false)
        .flush_interval(100ms)
        .build();
    
    ASSERT_TRUE(config.has_value());
    
    auto* logger = logln::Logger::create(*config);
    ASSERT_NE(logger, nullptr);
    
    logger->info("NoEncrypt", "This is an unencrypted message");
    
    logger->flush();
    std::this_thread::sleep_for(200ms);
    logln::Logger::release_all();
    std::this_thread::sleep_for(100ms);
    
    auto files = get_blog_files();
    ASSERT_FALSE(files.empty());
    
    // Decode with correct decompressor (should not need decryption)
    std::string decoded = decode_file_cpp(files[0], true, false);
    std::cout << "Decoded unencrypted log:\n" << decoded << std::endl;
    
    EXPECT_FALSE(decoded.starts_with("DECODE_ERROR"));
    EXPECT_TRUE(decoded.find("unencrypted message") != std::string::npos);
}

// ============================================================================
// Test 7: Sync Mode Encryption Test
// ============================================================================
TEST_F(EncryptionIntegrationTest, SyncModeEncryption) {
    std::cout << "\n=== Test 7: Sync Mode Encryption ===\n";
    
    auto config = logln::ConfigBuilder()
        .log_dir(test_log_dir_)
        .name("sync_test")
        .level(logln::Level::Debug)
        .sync()  // Sync mode
        .zstd(3)
        .encrypt(SERVER_PUBLIC_KEY)
        .console(false)
        .build();
    
    ASSERT_TRUE(config.has_value());
    
    auto* logger = logln::Logger::create(*config);
    ASSERT_NE(logger, nullptr);
    
    logger->info("Sync", "Sync mode message 1");
    logger->info("Sync", "Sync mode message 2");
    
    logger->flush();
    logln::Logger::release_all();
    std::this_thread::sleep_for(100ms);
    
    auto files = get_blog_files();
    ASSERT_FALSE(files.empty());
    
    std::string decoded = decode_file_cpp(files[0], true, true);
    std::cout << "Decoded sync mode log:\n" << decoded << std::endl;
    
    EXPECT_FALSE(decoded.starts_with("DECODE_ERROR"));
    EXPECT_TRUE(decoded.find("Sync mode message 1") != std::string::npos);
}

// ============================================================================
// Test 8: Raw File Hex Dump Debug
// ============================================================================
TEST_F(EncryptionIntegrationTest, HexDumpDebug) {
    std::cout << "\n=== Test 8: Hex Dump Debug ===\n";
    
    auto config = logln::ConfigBuilder()
        .log_dir(test_log_dir_)
        .name("hexdump_test")
        .level(logln::Level::Debug)
        .zstd(3)
        .encrypt(SERVER_PUBLIC_KEY)
        .console(false)
        .flush_interval(100ms)
        .build();
    
    ASSERT_TRUE(config.has_value());
    
    auto* logger = logln::Logger::create(*config);
    ASSERT_NE(logger, nullptr);
    
    logger->info("Hex", "Test");  // Very short message
    
    logger->flush();
    std::this_thread::sleep_for(200ms);
    logln::Logger::release_all();
    std::this_thread::sleep_for(100ms);
    
    auto files = get_blog_files();
    ASSERT_FALSE(files.empty());
    
    // Read file content
    std::ifstream file(files[0], std::ios::binary);
    std::vector<char> content_chars((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());
    std::vector<std::byte> content(content_chars.size());
    std::transform(content_chars.begin(), content_chars.end(), content.begin(),
                   [](char c) { return static_cast<std::byte>(c); });
    
    std::cout << "File size: " << content.size() << " bytes\n";
    std::cout << "First 256 bytes hex dump:\n";
    std::cout << logln::LogDecoder::hex_dump(content.data(), 
                                              std::min(content.size(), size_t(256)));
    
    // Try to decode
    std::string decoded = decode_file_cpp(files[0], true, true);
    std::cout << "\nDecoded: " << decoded << std::endl;
    
    // Even if decoding fails, mark test as complete (this is a debug test)
    if (decoded.starts_with("DECODE_ERROR")) {
        std::cout << "Decoding failed - this helps us debug the issue\n";
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
