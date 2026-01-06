// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "utils.hpp"
#include "log_header.hpp"

#include <sstream>
#include <iomanip>
#include <cctype>
#include <cstring>
#include <span>
#include <format>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#endif

namespace logln {

// ============================================================================
// Internal: Platform-specific localtime wrapper
// ============================================================================

namespace {

inline std::tm localtime_safe(std::time_t time) {
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &time);
#else
    localtime_r(&time, &tm_buf);
#endif
    return tm_buf;
}

inline double get_tz_offset(const std::tm& tm_buf) {
#ifdef _WIN32
    return static_cast<double>(-_timezone) / 3600.0;
#else
    return tm_buf.tm_gmtoff / 3600.0;
#endif
}

} // anonymous namespace

std::string hex_dump(const void* data, std::size_t len, 
                     std::size_t bytes_per_line) {
    if (!data || len == 0) return "";
    
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::ostringstream oss;
    
    for (std::size_t offset = 0; offset < len; offset += bytes_per_line) {
        // Address
        oss << std::setfill('0') << std::setw(8) << std::hex << offset << ": ";
        
        // Hex bytes
        std::size_t line_len = (std::min)(bytes_per_line, len - offset);
        for (std::size_t i = 0; i < bytes_per_line; ++i) {
            if (i < line_len) {
                oss << std::setfill('0') << std::setw(2) << std::hex 
                    << static_cast<int>(bytes[offset + i]) << ' ';
            } else {
                oss << "   ";
            }
            if (i == bytes_per_line / 2 - 1) {
                oss << ' ';  // Extra space in middle
            }
        }
        
        // ASCII representation
        oss << " |";
        for (std::size_t i = 0; i < line_len; ++i) {
            char c = static_cast<char>(bytes[offset + i]);
            oss << (std::isprint(static_cast<unsigned char>(c)) ? c : '.');
        }
        oss << "|\n";
    }
    
    return oss.str();
}

// ============================================================================
// Time Formatting Functions
// ============================================================================

std::string format_time_full(const Timestamp& tv) {
    auto tm_buf = localtime_safe(static_cast<std::time_t>(tv.tv_sec));
    double tz_offset = get_tz_offset(tm_buf);
    
    return std::format("{:04d}-{:02d}-{:02d} {:+.1f} {:02d}:{:02d}:{:02d}",
        1900 + tm_buf.tm_year, 1 + tm_buf.tm_mon, tm_buf.tm_mday,
        tz_offset, tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
}

std::string format_date_compact(const Timestamp& tv) {
    auto tm_buf = localtime_safe(static_cast<std::time_t>(tv.tv_sec));
    
    return std::format("{:04d}{:02d}{:02d}",
        1900 + tm_buf.tm_year, 1 + tm_buf.tm_mon, tm_buf.tm_mday);
}

std::string format_datetime_compact(const Timestamp& tv) {
    auto tm_buf = localtime_safe(static_cast<std::time_t>(tv.tv_sec));
    int millis = static_cast<int>(tv.tv_usec / 1000);
    
    return std::format("{:04d}{:02d}{:02d}_{:02d}{:02d}{:02d}_{:03d}",
        1900 + tm_buf.tm_year, 1 + tm_buf.tm_mon, tm_buf.tm_mday,
        tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, millis);
}

std::string format_timestamp_micros(const Timestamp& tv) {
    auto tm_buf = localtime_safe(static_cast<std::time_t>(tv.tv_sec));
    int micros = static_cast<int>(tv.tv_usec);
    
    return std::format("{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}.{:06d}",
        1900 + tm_buf.tm_year, 1 + tm_buf.tm_mon, tm_buf.tm_mday,
        tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, micros);
}

std::string format_timestamp(const Timestamp& tv) {
    auto tm_buf = localtime_safe(static_cast<std::time_t>(tv.tv_sec));
    double tz_offset = get_tz_offset(tm_buf);
    
    return std::format("{:04d}-{:02d}-{:02d} {:+.1f} {:02d}:{:02d}:{:02d}.{:03d}",
        1900 + tm_buf.tm_year, 1 + tm_buf.tm_mon, tm_buf.tm_mday,
        tz_offset, tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
        static_cast<int>(tv.tv_usec / 1000));
}

std::string format_date(const Timestamp& tv) {
    auto tm_buf = localtime_safe(static_cast<std::time_t>(tv.tv_sec));
    
    return std::format("{:04d}-{:02d}-{:02d}",
        1900 + tm_buf.tm_year, 1 + tm_buf.tm_mon, tm_buf.tm_mday);
}

// ============================================================================
// Log Header Analysis
// ============================================================================

std::string dump_with_header(const void* data, std::size_t len) {
    if (!data || len == 0) return "";
    
    std::ostringstream oss;
    
    oss << "=== Log Record Dump ===\n";
    oss << "Total size: " << len << " bytes\n";
    
    // Try to parse header
    if (len >= LogHeader::kHeaderSize + LogHeader::kTailerSize) {
        const auto* header = static_cast<const std::byte*>(data);
        char magic = static_cast<char>(header[0]);
        
        if (LogMagicNum::is_valid_start(magic)) {
            std::uint32_t length = 0;
            std::memcpy(&length, header + 5, 4);
            
            oss << "Header: Valid\n";
            oss << "  Compressed: " << (LogMagicNum::is_compressed(magic) ? "Yes" : "No") << "\n";
            oss << "  Encrypted: " << (LogMagicNum::is_encrypted(magic) ? "Yes" : "No") << "\n";
            oss << "  Data length: " << length << "\n";
        } else {
            oss << "Header: Invalid\n";
        }
    } else {
        oss << "Header: Too short\n";
    }
    
    oss << "\n--- Raw Hex Dump ---\n";
    oss << hex_dump(data, len);
    
    return oss.str();
}

} // namespace logln
