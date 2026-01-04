// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors
//
// ChaCha20 Encryptor with ECDH key exchange
// Uses Monocypher (BSD-2/CC0) for XChaCha20 symmetric encryption
// Uses micro-ecc for secp256k1 ECDH key exchange

#include "encryptor.hpp"
#include <monocypher.h>
#include <uECC.h>

#include <cstring>
#include <array>
#include <random>

namespace logln {

namespace {

// Hex string to bytes
bool hex_to_bytes(std::string_view hex, std::span<std::uint8_t> out) {
    if (hex.size() != out.size() * 2) return false;
    
    for (std::size_t i = 0; i < out.size(); ++i) {
        char hi = hex[i * 2];
        char lo = hex[i * 2 + 1];
        
        auto hex_val = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        
        int hi_val = hex_val(hi);
        int lo_val = hex_val(lo);
        
        if (hi_val < 0 || lo_val < 0) return false;
        
        out[i] = static_cast<std::uint8_t>((hi_val << 4) | lo_val);
    }
    
    return true;
}

// Random number generator for micro-ecc
int rng_function(uint8_t* dest, unsigned size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (unsigned i = 0; i < size; ++i) {
        dest[i] = static_cast<uint8_t>(dis(gen));
    }
    return 1;
}

} // anonymous namespace

// ============================================================================
// ChaCha20Encryptor Implementation
// ============================================================================

struct ChaCha20Encryptor::Impl {
    std::array<std::uint8_t, kKeySize> key{};           // 256-bit ChaCha20 key
    std::array<std::uint8_t, kNonceSize> nonce{};       // 192-bit nonce (XChaCha20)
    std::array<std::uint8_t, kPublicKeySize> client_pubkey{};
    std::uint64_t counter = 0;  // Encryption counter for unique nonces
    bool active = false;
    
    explicit Impl(std::string_view server_pub_key_hex) {
        if (server_pub_key_hex.size() != kPublicKeySize * 2) {
            return;
        }
        
        // Parse server public key from hex
        std::array<std::uint8_t, kPublicKeySize> server_pubkey{};
        if (!hex_to_bytes(server_pub_key_hex, server_pubkey)) {
            return;
        }
        
        // Set RNG for micro-ecc
        uECC_set_rng(rng_function);
        
        // Get curve (secp256k1)
        const struct uECC_Curve_t* curve = uECC_secp256k1();
        
        // Generate client keypair
        std::array<std::uint8_t, 32> client_privkey{};
        if (!uECC_make_key(client_pubkey.data(), client_privkey.data(), curve)) {
            return;
        }
        
        // Compute ECDH shared secret (32 bytes)
        std::array<std::uint8_t, 32> shared_secret{};
        if (!uECC_shared_secret(server_pubkey.data(), client_privkey.data(), 
                                 shared_secret.data(), curve)) {
            return;
        }
        
        // Use shared secret directly as ChaCha20 key (both are 256-bit)
        std::memcpy(key.data(), shared_secret.data(), kKeySize);
        
        // Initialize nonce with random bytes (first 16 bytes random, last 8 for counter)
        rng_function(nonce.data(), 16);
        std::memset(nonce.data() + 16, 0, 8);  // Clear counter portion
        
        // Wipe private key from memory
        crypto_wipe(client_privkey.data(), client_privkey.size());
        crypto_wipe(shared_secret.data(), shared_secret.size());
        
        active = true;
    }
    
    ~Impl() {
        // Secure cleanup
        crypto_wipe(key.data(), key.size());
        crypto_wipe(nonce.data(), nonce.size());
    }
};

ChaCha20Encryptor::ChaCha20Encryptor(std::string_view server_pub_key)
    : impl_(std::make_unique<Impl>(server_pub_key)) {
}

ChaCha20Encryptor::~ChaCha20Encryptor() = default;

ChaCha20Encryptor::ChaCha20Encryptor(ChaCha20Encryptor&&) noexcept = default;
ChaCha20Encryptor& ChaCha20Encryptor::operator=(ChaCha20Encryptor&&) noexcept = default;

std::expected<std::size_t, int>
ChaCha20Encryptor::encrypt(std::span<const std::byte> input, 
                           std::span<std::byte> output) {
    if (output.size() < input.size()) {
        return std::unexpected(-1);
    }
    
    if (!impl_->active) {
        // No encryption, just copy
        std::copy(input.begin(), input.end(), output.begin());
        return input.size();
    }
    
    // Build unique nonce: [16 bytes random][8 bytes counter]
    std::array<std::uint8_t, kNonceSize> current_nonce;
    std::memcpy(current_nonce.data(), impl_->nonce.data(), 16);
    std::uint64_t ctr = impl_->counter++;
    std::memcpy(current_nonce.data() + 16, &ctr, 8);
    
    // XChaCha20 encryption (stream cipher, XOR-based)
    crypto_chacha20_x(
        reinterpret_cast<std::uint8_t*>(output.data()),
        reinterpret_cast<const std::uint8_t*>(input.data()),
        input.size(),
        impl_->key.data(),
        current_nonce.data(),
        0  // Initial counter
    );
    
    return input.size();
}

std::span<const std::byte> ChaCha20Encryptor::public_key() const {
    return std::as_bytes(std::span{impl_->client_pubkey});
}

bool ChaCha20Encryptor::is_active() const noexcept {
    return impl_->active;
}

std::expected<std::vector<std::byte>, int>
ChaCha20Encryptor::decrypt(std::span<const std::byte> input) {
    std::vector<std::byte> output(input.size());
    
    if (!impl_->active) {
        // No decryption needed
        std::copy(input.begin(), input.end(), output.begin());
        return output;
    }
    
    // Build nonce with current counter
    std::array<std::uint8_t, kNonceSize> current_nonce;
    std::memcpy(current_nonce.data(), impl_->nonce.data(), 16);
    std::uint64_t ctr = impl_->counter++;
    std::memcpy(current_nonce.data() + 16, &ctr, 8);
    
    // XChaCha20 decryption (same as encryption - XOR operation)
    crypto_chacha20_x(
        reinterpret_cast<std::uint8_t*>(output.data()),
        reinterpret_cast<const std::uint8_t*>(input.data()),
        input.size(),
        impl_->key.data(),
        current_nonce.data(),
        0  // Initial counter
    );
    
    return output;
}

// ============================================================================
// Factory Functions
// ============================================================================

std::unique_ptr<IEncryptor> make_encryptor(std::string_view server_pub_key) {
    return std::make_unique<ChaCha20Encryptor>(server_pub_key);
}

// ============================================================================
// ChaCha20Decryptor - Server-side decryptor
// ============================================================================

class ChaCha20Decryptor : public IEncryptor {
public:
    static constexpr std::size_t kKeySize = 32;
    static constexpr std::size_t kNonceSize = 24;
    
    ChaCha20Decryptor(std::span<const std::byte> client_pub_key,
                      std::string_view server_priv_key_hex) {
        if (client_pub_key.size() != 64 || server_priv_key_hex.size() != 64) {
            return;
        }
        
        // Parse server private key from hex
        std::array<std::uint8_t, 32> server_privkey{};
        if (!hex_to_bytes(server_priv_key_hex, server_privkey)) {
            return;
        }
        
        // Get client public key
        std::array<std::uint8_t, 64> client_pubkey{};
        std::memcpy(client_pubkey.data(), client_pub_key.data(), 64);
        
        // Get curve (secp256k1)
        const struct uECC_Curve_t* curve = uECC_secp256k1();
        
        // Compute ECDH shared secret (same as encryption side)
        std::array<std::uint8_t, 32> shared_secret{};
        if (!uECC_shared_secret(client_pubkey.data(), server_privkey.data(),
                                 shared_secret.data(), curve)) {
            return;
        }
        
        // Use shared secret as ChaCha20 key
        std::memcpy(key_.data(), shared_secret.data(), kKeySize);
        
        // Initialize nonce (will be set by set_nonce)
        std::memset(nonce_.data(), 0, kNonceSize);
        
        // Wipe sensitive data
        crypto_wipe(server_privkey.data(), server_privkey.size());
        crypto_wipe(shared_secret.data(), shared_secret.size());
        
        active_ = true;
    }
    
    ~ChaCha20Decryptor() override {
        crypto_wipe(key_.data(), key_.size());
        crypto_wipe(nonce_.data(), nonce_.size());
    }
    
    std::expected<std::size_t, int>
    encrypt(std::span<const std::byte> input, 
            std::span<std::byte> output) override {
        // Decryptor doesn't encrypt
        if (output.size() < input.size()) {
            return std::unexpected(-1);
        }
        std::copy(input.begin(), input.end(), output.begin());
        return input.size();
    }
    
    std::expected<std::vector<std::byte>, int>
    decrypt(std::span<const std::byte> input) override {
        std::vector<std::byte> output(input.size());
        
        if (!active_) {
            std::copy(input.begin(), input.end(), output.begin());
            return output;
        }
        
        // Build nonce with current counter
        std::array<std::uint8_t, kNonceSize> current_nonce;
        std::memcpy(current_nonce.data(), nonce_.data(), 16);
        std::uint64_t ctr = counter_++;
        std::memcpy(current_nonce.data() + 16, &ctr, 8);
        
        crypto_chacha20_x(
            reinterpret_cast<std::uint8_t*>(output.data()),
            reinterpret_cast<const std::uint8_t*>(input.data()),
            input.size(),
            key_.data(),
            current_nonce.data(),
            0
        );
        
        return output;
    }
    
    std::span<const std::byte> public_key() const override {
        return {};
    }
    
    bool is_active() const noexcept override {
        return active_;
    }
    
    // Set nonce (must match encryptor's nonce for decryption to work)
    void set_nonce(std::span<const std::uint8_t> nonce) {
        if (nonce.size() >= 16) {
            std::memcpy(nonce_.data(), nonce.data(), 16);
        }
    }
    
    // Reset counter for synchronized decryption
    void reset_counter(std::uint64_t value = 0) {
        counter_ = value;
    }
    
private:
    std::array<std::uint8_t, kKeySize> key_{};
    std::array<std::uint8_t, kNonceSize> nonce_{};
    std::uint64_t counter_ = 0;
    bool active_ = false;
};

std::unique_ptr<IEncryptor> create_decryptor(
    std::span<const std::byte> client_pub_key,
    std::string_view server_priv_key_hex) {
    return std::make_unique<ChaCha20Decryptor>(client_pub_key, server_priv_key_hex);
}

} // namespace logln

