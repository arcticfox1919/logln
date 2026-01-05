// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <chrono>
#include <source_location>

namespace logln {

// ============================================================================
// Timestamp 
// ============================================================================

struct Timestamp {
    std::int64_t tv_sec = 0;   // Seconds since epoch
    std::int64_t tv_usec = 0;  // Microseconds
    
    // Create from current time
    static Timestamp now() noexcept {
        auto tp = std::chrono::system_clock::now();
        auto sec = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch());
        auto usec = std::chrono::duration_cast<std::chrono::microseconds>(tp.time_since_epoch()) - sec;
        return {sec.count(), usec.count()};
    }
};

// ============================================================================
// Log Levels
// ============================================================================

enum class Level : std::uint8_t {
    Verbose = 0,  // Extremely detailed, usually disabled
    Debug,        // Detailed information for debugging
    Info,         // General runtime events
    Warn,         // Unexpected situations, not errors
    Error,        // Runtime errors, recoverable
    Fatal,        // Severe errors, may crash
    Off           // Disable all logging
};

[[nodiscard]] constexpr std::string_view level_name(Level level) noexcept {
    switch (level) {
        case Level::Verbose: return "V";
        case Level::Debug:   return "D";
        case Level::Info:    return "I";
        case Level::Warn:    return "W";
        case Level::Error:   return "E";
        case Level::Fatal:   return "F";
        case Level::Off:     return "O";
    }
    return "?";
}

[[nodiscard]] constexpr std::string_view level_full_name(Level level) noexcept {
    switch (level) {
        case Level::Verbose: return "VERBOSE";
        case Level::Debug:   return "DEBUG";
        case Level::Info:    return "INFO";
        case Level::Warn:    return "WARN";
        case Level::Error:   return "ERROR";
        case Level::Fatal:   return "FATAL";
        case Level::Off:     return "OFF";
    }
    return "UNKNOWN";
}

// ============================================================================
// Write Mode
// ============================================================================

enum class WriteMode : std::uint8_t {
    Async,  // Buffered async write (default, high performance)
    Sync    // Immediate sync write (for debugging)
};

// ============================================================================
// Compression Mode
// ============================================================================

enum class Compression : std::uint8_t {
    None = 0,
    Zstd = 1
};

// ============================================================================
// Log Record
// ============================================================================

struct Record {
    Level level = Level::Info;
    std::string_view tag;
    std::string_view message;
    std::source_location location;
    
    // Timing
    Timestamp timestamp{};
    
    // Thread/Process info
    std::int64_t pid = 0;
    std::int64_t tid = 0;
    std::int64_t main_tid = 0;
    
    [[nodiscard]] constexpr bool is_main_thread() const noexcept {
        return tid == main_tid;
    }
};

// ============================================================================
// File I/O Action Results
// ============================================================================

enum class IOResult : std::uint8_t {
    Success = 0,
    Unnecessary,
    OpenFailed,
    ReadFailed,
    WriteFailed,
    CloseFailed,
    RemoveFailed
};

// ============================================================================
// Magic Numbers for Log Format
// ============================================================================

namespace magic {
    // Start markers (simplified: only distinguish features, not write mode)
    // Format: 0x06 + (compressed ? 1 : 0) + (encrypted ? 2 : 0)
    constexpr std::uint8_t kNoFeature      = 0x06;
    constexpr std::uint8_t kCompressed     = 0x07;
    constexpr std::uint8_t kEncrypted      = 0x08;
    constexpr std::uint8_t kCompEncrypted  = 0x09;
    
    // End marker
    constexpr std::uint8_t kEnd            = 0x00;
    
    [[nodiscard]] constexpr bool is_valid_start(std::uint8_t byte) noexcept {
        return byte >= 0x06 && byte <= 0x09;
    }
    
    [[nodiscard]] constexpr bool is_compressed(std::uint8_t byte) noexcept {
        return (byte & 0x01) != 0;
    }
    
    [[nodiscard]] constexpr bool is_encrypted(std::uint8_t byte) noexcept {
        return (byte & 0x02) != 0;
    }
}

} // namespace logln
