// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <memory>
#include <expected>
#include <array>
#include <vector>

namespace logln {

// ============================================================================
// Encryptor Interface
// ============================================================================

class IEncryptor {
public:
    virtual ~IEncryptor() = default;
    
    // Encrypt data in-place or to output buffer
    [[nodiscard]] virtual std::expected<std::size_t, int>
    encrypt(std::span<const std::byte> input, 
            std::span<std::byte> output) = 0;
    
    // Decrypt data
    [[nodiscard]] virtual std::expected<std::vector<std::byte>, int>
    decrypt(std::span<const std::byte> input) = 0;
    
    // Get client public key for header
    [[nodiscard]] virtual std::span<const std::byte> public_key() const = 0;
    
    // Check if encryption is active
    [[nodiscard]] virtual bool is_active() const noexcept = 0;
};

// ============================================================================
// ChaCha20 Encryptor - High-performance stream cipher with ECDH key exchange
// ============================================================================

class ChaCha20Encryptor : public IEncryptor {
public:
    // Public key size (for ECDH, secp256k1 uncompressed)
    static constexpr std::size_t kPublicKeySize = 64;
    
    // ChaCha20 key size (256-bit)
    static constexpr std::size_t kKeySize = 32;
    
    // XChaCha20 nonce size (192-bit)
    static constexpr std::size_t kNonceSize = 24;
    
    // Create encryptor with server public key (hex string, 128 chars)
    explicit ChaCha20Encryptor(std::string_view server_pub_key);
    ~ChaCha20Encryptor() override;
    
    // Non-copyable
    ChaCha20Encryptor(const ChaCha20Encryptor&) = delete;
    ChaCha20Encryptor& operator=(const ChaCha20Encryptor&) = delete;
    
    // Movable
    ChaCha20Encryptor(ChaCha20Encryptor&&) noexcept;
    ChaCha20Encryptor& operator=(ChaCha20Encryptor&&) noexcept;
    
    // IEncryptor interface
    [[nodiscard]] std::expected<std::size_t, int>
    encrypt(std::span<const std::byte> input, 
            std::span<std::byte> output) override;
    
    [[nodiscard]] std::expected<std::vector<std::byte>, int>
    decrypt(std::span<const std::byte> input) override;
    
    [[nodiscard]] std::span<const std::byte> public_key() const override;
    
    [[nodiscard]] bool is_active() const noexcept override;
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Factory
// ============================================================================

[[nodiscard]] std::unique_ptr<IEncryptor> make_encryptor(std::string_view server_pub_key);

// Create decryptor from client public key (64 bytes) and server private key (32 bytes hex = 64 chars)
[[nodiscard]] std::unique_ptr<IEncryptor> create_decryptor(
    std::span<const std::byte> client_pub_key,
    std::string_view server_priv_key_hex);

// ============================================================================
// Null Encryptor (no-op)
// ============================================================================

class NullEncryptor : public IEncryptor {
public:
    [[nodiscard]] std::expected<std::size_t, int>
    encrypt(std::span<const std::byte> input, 
            std::span<std::byte> output) override {
        if (output.size() < input.size()) {
            return std::unexpected(-1);
        }
        std::copy(input.begin(), input.end(), output.begin());
        return input.size();
    }
    
    [[nodiscard]] std::expected<std::vector<std::byte>, int>
    decrypt(std::span<const std::byte> input) override {
        return std::vector<std::byte>(input.begin(), input.end());
    }
    
    [[nodiscard]] std::span<const std::byte> public_key() const override {
        return {};
    }
    
    [[nodiscard]] bool is_active() const noexcept override {
        return false;
    }
};

} // namespace logln
