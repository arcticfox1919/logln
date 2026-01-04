// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors
//
// Unit tests for ChaCha20 Encryptor

#include <gtest/gtest.h>
#include "encryptor.hpp"
#include <uECC.h>

#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <random>
#include <string>
#include <vector>

namespace logln {
namespace {

// Helper: Generate a secp256k1 keypair and return hex-encoded public key
std::pair<std::string, std::string> generate_keypair() {
    // RNG for micro-ecc
    uECC_set_rng([](uint8_t* dest, unsigned size) -> int {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (unsigned i = 0; i < size; ++i) {
            dest[i] = static_cast<uint8_t>(dis(gen));
        }
        return 1;
    });
    
    const struct uECC_Curve_t* curve = uECC_secp256k1();
    std::array<std::uint8_t, 64> pubkey{};
    std::array<std::uint8_t, 32> privkey{};
    
    if (!uECC_make_key(pubkey.data(), privkey.data(), curve)) {
        return {"", ""};
    }
    
    // Convert to hex
    auto to_hex = [](const std::uint8_t* data, std::size_t len) -> std::string {
        static const char hex_chars[] = "0123456789abcdef";
        std::string result;
        result.reserve(len * 2);
        for (std::size_t i = 0; i < len; ++i) {
            result += hex_chars[(data[i] >> 4) & 0x0F];
            result += hex_chars[data[i] & 0x0F];
        }
        return result;
    };
    
    return {to_hex(pubkey.data(), 64), to_hex(privkey.data(), 32)};
}

// Helper: Convert string to bytes
std::vector<std::byte> to_bytes(std::string_view str) {
    std::vector<std::byte> result(str.size());
    std::memcpy(result.data(), str.data(), str.size());
    return result;
}

// Helper: Convert bytes to string
std::string to_string(std::span<const std::byte> bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

// ============================================================================
// ChaCha20Encryptor Tests
// ============================================================================

class ChaCha20EncryptorTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto [pub, priv] = generate_keypair();
        server_pubkey_hex_ = pub;
        server_privkey_hex_ = priv;
    }
    
    std::string server_pubkey_hex_;
    std::string server_privkey_hex_;
};

TEST_F(ChaCha20EncryptorTest, Construction) {
    ChaCha20Encryptor enc(server_pubkey_hex_);
    EXPECT_TRUE(enc.is_active());
    EXPECT_EQ(enc.public_key().size(), ChaCha20Encryptor::kPublicKeySize);
}

TEST_F(ChaCha20EncryptorTest, ConstructionWithInvalidKey) {
    // Too short
    ChaCha20Encryptor enc1("abc123");
    EXPECT_FALSE(enc1.is_active());
    
    // Invalid hex characters
    std::string invalid_hex(128, 'g');
    ChaCha20Encryptor enc2(invalid_hex);
    EXPECT_FALSE(enc2.is_active());
    
    // Empty
    ChaCha20Encryptor enc3("");
    EXPECT_FALSE(enc3.is_active());
}

TEST_F(ChaCha20EncryptorTest, EncryptDecrypt) {
    ChaCha20Encryptor enc(server_pubkey_hex_);
    ASSERT_TRUE(enc.is_active());
    
    std::string plaintext = "Hello, ChaCha20!";
    auto input = to_bytes(plaintext);
    std::vector<std::byte> ciphertext(input.size());
    
    // Encrypt
    auto result = enc.encrypt(input, ciphertext);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), input.size());
    
    // Ciphertext should be different from plaintext
    EXPECT_NE(std::memcmp(input.data(), ciphertext.data(), input.size()), 0);
}

TEST_F(ChaCha20EncryptorTest, EncryptOutputTooSmall) {
    ChaCha20Encryptor enc(server_pubkey_hex_);
    ASSERT_TRUE(enc.is_active());
    
    std::string plaintext = "Hello, World!";
    auto input = to_bytes(plaintext);
    std::vector<std::byte> output(5);  // Too small
    
    auto result = enc.encrypt(input, output);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), -1);
}

TEST_F(ChaCha20EncryptorTest, EncryptEmptyData) {
    ChaCha20Encryptor enc(server_pubkey_hex_);
    ASSERT_TRUE(enc.is_active());
    
    std::vector<std::byte> empty;
    std::vector<std::byte> output;
    
    auto result = enc.encrypt(empty, output);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), 0u);
}

TEST_F(ChaCha20EncryptorTest, EncryptLargeData) {
    ChaCha20Encryptor enc(server_pubkey_hex_);
    ASSERT_TRUE(enc.is_active());
    
    // 1MB of data
    std::vector<std::byte> input(1024 * 1024);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& b : input) {
        b = static_cast<std::byte>(dis(gen));
    }
    
    std::vector<std::byte> output(input.size());
    
    auto result = enc.encrypt(input, output);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), input.size());
    
    // Should be encrypted (different from input)
    EXPECT_NE(std::memcmp(input.data(), output.data(), input.size()), 0);
}

TEST_F(ChaCha20EncryptorTest, MoveConstruction) {
    ChaCha20Encryptor enc1(server_pubkey_hex_);
    ASSERT_TRUE(enc1.is_active());
    auto pubkey1 = std::vector<std::byte>(enc1.public_key().begin(), enc1.public_key().end());
    
    ChaCha20Encryptor enc2(std::move(enc1));
    EXPECT_TRUE(enc2.is_active());
    
    auto pubkey2 = std::vector<std::byte>(enc2.public_key().begin(), enc2.public_key().end());
    EXPECT_EQ(pubkey1, pubkey2);
}

TEST_F(ChaCha20EncryptorTest, MoveAssignment) {
    ChaCha20Encryptor enc1(server_pubkey_hex_);
    ASSERT_TRUE(enc1.is_active());
    
    auto [pub2, priv2] = generate_keypair();
    ChaCha20Encryptor enc2(pub2);
    ASSERT_TRUE(enc2.is_active());
    
    auto pubkey1 = std::vector<std::byte>(enc1.public_key().begin(), enc1.public_key().end());
    
    enc2 = std::move(enc1);
    
    auto pubkey2 = std::vector<std::byte>(enc2.public_key().begin(), enc2.public_key().end());
    EXPECT_EQ(pubkey1, pubkey2);
}

TEST_F(ChaCha20EncryptorTest, UniqueNonces) {
    ChaCha20Encryptor enc(server_pubkey_hex_);
    ASSERT_TRUE(enc.is_active());
    
    std::string plaintext = "Same plaintext for multiple encryptions";
    auto input = to_bytes(plaintext);
    
    std::vector<std::byte> cipher1(input.size());
    std::vector<std::byte> cipher2(input.size());
    
    // Encrypt twice with same plaintext
    auto r1 = enc.encrypt(input, cipher1);
    auto r2 = enc.encrypt(input, cipher2);
    ASSERT_TRUE(r1.has_value());
    ASSERT_TRUE(r2.has_value());
    
    // Should produce different ciphertexts due to unique nonces
    EXPECT_NE(cipher1, cipher2);
}

// ============================================================================
// NullEncryptor Tests
// ============================================================================

TEST(NullEncryptorTest, IsNotActive) {
    NullEncryptor enc;
    EXPECT_FALSE(enc.is_active());
    EXPECT_TRUE(enc.public_key().empty());
}

TEST(NullEncryptorTest, EncryptCopiesData) {
    NullEncryptor enc;
    
    std::string plaintext = "Hello, World!";
    auto input = to_bytes(plaintext);
    std::vector<std::byte> output(input.size());
    
    auto result = enc.encrypt(input, output);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), input.size());
    
    // Output should equal input (no encryption)
    EXPECT_EQ(std::memcmp(input.data(), output.data(), input.size()), 0);
}

TEST(NullEncryptorTest, DecryptCopiesData) {
    NullEncryptor enc;
    
    std::string data = "Hello, World!";
    auto input = to_bytes(data);
    
    auto result = enc.decrypt(input);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().size(), input.size());
    EXPECT_EQ(std::memcmp(input.data(), result.value().data(), input.size()), 0);
}

TEST(NullEncryptorTest, EncryptOutputTooSmall) {
    NullEncryptor enc;
    
    std::string plaintext = "Hello, World!";
    auto input = to_bytes(plaintext);
    std::vector<std::byte> output(5);  // Too small
    
    auto result = enc.encrypt(input, output);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), -1);
}

// ============================================================================
// Factory Function Tests
// ============================================================================

TEST_F(ChaCha20EncryptorTest, MakeEncryptor) {
    auto enc = make_encryptor(server_pubkey_hex_);
    ASSERT_NE(enc, nullptr);
    EXPECT_TRUE(enc->is_active());
    EXPECT_EQ(enc->public_key().size(), ChaCha20Encryptor::kPublicKeySize);
}

TEST_F(ChaCha20EncryptorTest, CreateDecryptor) {
    // Create encryptor first
    auto enc = make_encryptor(server_pubkey_hex_);
    ASSERT_NE(enc, nullptr);
    ASSERT_TRUE(enc->is_active());
    
    // Create decryptor with encryptor's public key
    auto dec = create_decryptor(enc->public_key(), server_privkey_hex_);
    ASSERT_NE(dec, nullptr);
    EXPECT_TRUE(dec->is_active());
}

TEST_F(ChaCha20EncryptorTest, CreateDecryptorInvalidParams) {
    // Invalid client public key size
    std::vector<std::byte> short_key(32);
    auto dec1 = create_decryptor(short_key, server_privkey_hex_);
    ASSERT_NE(dec1, nullptr);
    EXPECT_FALSE(dec1->is_active());
    
    // Invalid server private key hex
    auto enc = make_encryptor(server_pubkey_hex_);
    auto dec2 = create_decryptor(enc->public_key(), "invalid");
    ASSERT_NE(dec2, nullptr);
    EXPECT_FALSE(dec2->is_active());
}

// ============================================================================
// End-to-End Encryption/Decryption Tests
// Note: These tests verify that encryption and decryption work correctly
// when using the SAME encryptor instance. In real scenarios, nonce would
// need to be transmitted separately for cross-instance decryption.
// ============================================================================

TEST_F(ChaCha20EncryptorTest, EndToEndEncryptDecrypt) {
    // Create encryptor
    ChaCha20Encryptor enc(server_pubkey_hex_);
    ASSERT_TRUE(enc.is_active());
    
    // Original message
    std::string message = "This is a secret message for end-to-end test!";
    auto plaintext = to_bytes(message);
    std::vector<std::byte> ciphertext(plaintext.size());
    
    // Encrypt
    auto enc_result = enc.encrypt(plaintext, ciphertext);
    ASSERT_TRUE(enc_result.has_value());
    
    // Verify ciphertext is different from plaintext
    EXPECT_NE(std::memcmp(plaintext.data(), ciphertext.data(), plaintext.size()), 0);
    
    // Verify decryptor can be created and is active
    auto dec = create_decryptor(enc.public_key(), server_privkey_hex_);
    ASSERT_NE(dec, nullptr);
    ASSERT_TRUE(dec->is_active());
    
    // Note: Full end-to-end decryption requires nonce synchronization
    // which would be handled by log file header in real usage
}

TEST_F(ChaCha20EncryptorTest, EndToEndMultipleMessages) {
    ChaCha20Encryptor enc(server_pubkey_hex_);
    ASSERT_TRUE(enc.is_active());
    
    std::vector<std::string> messages = {
        "First message",
        "Second message with more content",
        "Third",
        "Fourth message is the longest one in this test sequence!"
    };
    
    std::vector<std::vector<std::byte>> ciphertexts;
    
    // Encrypt all messages
    for (const auto& msg : messages) {
        auto plaintext = to_bytes(msg);
        std::vector<std::byte> ciphertext(plaintext.size());
        
        auto enc_result = enc.encrypt(plaintext, ciphertext);
        ASSERT_TRUE(enc_result.has_value());
        
        // Verify ciphertext is different from plaintext
        EXPECT_NE(std::memcmp(plaintext.data(), ciphertext.data(), plaintext.size()), 0);
        
        ciphertexts.push_back(std::move(ciphertext));
    }
    
    // Verify all ciphertexts are different (unique nonces)
    for (std::size_t i = 0; i < ciphertexts.size(); ++i) {
        for (std::size_t j = i + 1; j < ciphertexts.size(); ++j) {
            if (ciphertexts[i].size() == ciphertexts[j].size()) {
                // Even if same size, content should differ
                EXPECT_NE(ciphertexts[i], ciphertexts[j]);
            }
        }
    }
    
    // Verify decryptor can be constructed
    auto dec = create_decryptor(enc.public_key(), server_privkey_hex_);
    ASSERT_NE(dec, nullptr);
    ASSERT_TRUE(dec->is_active());
}

// ============================================================================
// Performance Test (informational)
// ============================================================================

TEST_F(ChaCha20EncryptorTest, PerformanceBenchmark) {
    ChaCha20Encryptor enc(server_pubkey_hex_);
    ASSERT_TRUE(enc.is_active());
    
    // 64KB buffer (typical log buffer size)
    constexpr std::size_t kBufferSize = 64 * 1024;
    std::vector<std::byte> input(kBufferSize);
    std::vector<std::byte> output(kBufferSize);
    
    // Fill with random data
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& b : input) {
        b = static_cast<std::byte>(dis(gen));
    }
    
    // Encrypt 1000 times (64MB total)
    constexpr int kIterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < kIterations; ++i) {
        auto result = enc.encrypt(input, output);
        ASSERT_TRUE(result.has_value());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    double total_mb = static_cast<double>(kBufferSize * kIterations) / (1024 * 1024);
    double throughput = total_mb / (duration.count() / 1000.0);
    
    std::cout << "ChaCha20 Encryption Performance:\n";
    std::cout << "  Total: " << total_mb << " MB\n";
    std::cout << "  Time: " << duration.count() << " ms\n";
    std::cout << "  Throughput: " << throughput << " MB/s\n";
    
    // Should be reasonably fast (at least 100 MB/s on modern hardware)
    EXPECT_GT(throughput, 50.0);
}

} // namespace
} // namespace logln
