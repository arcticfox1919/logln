// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "logln/formatter.hpp"
#include "logln/platform.hpp"

#include <array>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <unordered_map>

namespace logln {

// ============================================================================
// Token types for pattern parsing
// ============================================================================

enum class TokenType : std::uint8_t {
    Literal,
    Level,
    LevelFull,
    Time,
    Time6,      // 6-digit microseconds: YYYY-MM-DD HH:MM:SS.uuuuuu
    Date,
    Pid,
    Tid,
    TidStar,
    Tag,
    File,
    Path,
    Line,
    Func,
    Message,
    Newline
};

struct Token {
    TokenType type;
    std::string literal;  // Only used for Literal type
};

// ============================================================================
// Token lookup table (hash map for O(1) lookup)
// ============================================================================

namespace {

// Static token name to type mapping
const std::unordered_map<std::string_view, TokenType>& get_token_map() {
    static const std::unordered_map<std::string_view, TokenType> map = {
        {"level", TokenType::Level},
        {"Level", TokenType::LevelFull},
        {"time",  TokenType::Time},
        {"time6", TokenType::Time6},
        {"date",  TokenType::Date},
        {"pid",   TokenType::Pid},
        {"tid",   TokenType::Tid},
        {"tid*",  TokenType::TidStar},
        {"tag",   TokenType::Tag},
        {"file",  TokenType::File},
        {"path",  TokenType::Path},
        {"line",  TokenType::Line},
        {"func",  TokenType::Func},
        {"msg",   TokenType::Message},
        {"n",     TokenType::Newline},
    };
    return map;
}

// Fast integer to string conversion
inline void append_uint64(std::string& out, std::uint64_t value) {
    std::array<char, 20> buf;
    auto [ptr, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), value);
    out.append(buf.data(), ptr - buf.data());
}

inline void append_uint32(std::string& out, std::uint32_t value) {
    std::array<char, 10> buf;
    auto [ptr, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), value);
    out.append(buf.data(), ptr - buf.data());
}

}  // namespace

// ============================================================================
// Formatter Implementation
// ============================================================================

struct Formatter::Impl {
    std::string pattern;
    std::vector<Token> tokens;
    
    void parse_pattern(std::string_view pat) {
        pattern = std::string(pat);
        tokens.clear();
        tokens.reserve(16);  // Pre-allocate for typical patterns
        
        const auto& token_map = get_token_map();
        std::string_view remaining = pat;
        std::string current_literal;
        current_literal.reserve(64);  // Pre-allocate
        
        while (!remaining.empty()) {
            // Look for next {
            auto pos = remaining.find('{');
            
            if (pos == std::string_view::npos) {
                // No more tokens, rest is literal
                current_literal.append(remaining);
                remaining = {};
            } else if (pos > 0) {
                // Literal before token
                current_literal.append(remaining.substr(0, pos));
                remaining.remove_prefix(pos);
            } else {
                // Starts with {, find closing }
                auto end_pos = remaining.find('}');
                if (end_pos == std::string_view::npos) {
                    // Invalid, treat as literal
                    current_literal.append(remaining);
                    remaining = {};
                } else {
                    // Flush literal
                    if (!current_literal.empty()) {
                        tokens.push_back({TokenType::Literal, std::move(current_literal)});
                        current_literal.clear();
                        current_literal.reserve(64);
                    }
                    
                    // Parse token using hash map lookup (O(1) instead of O(n) comparisons)
                    auto token_name = remaining.substr(1, end_pos - 1);
                    remaining.remove_prefix(end_pos + 1);
                    
                    if (auto it = token_map.find(token_name); it != token_map.end()) {
                        tokens.push_back({it->second, {}});
                    } else {
                        // Unknown token, treat as literal
                        current_literal.push_back('{');
                        current_literal.append(token_name);
                        current_literal.push_back('}');
                    }
                }
            }
        }
        
        // Flush remaining literal
        if (!current_literal.empty()) {
            tokens.push_back({TokenType::Literal, std::move(current_literal)});
        }
        
        tokens.shrink_to_fit();
    }
    
    // Core formatting: direct write to buffer (zero allocation in hot path)
    // Returns: bytes written (not including null terminator)
    //
    // Optimization notes:
    // - [[likely]] hints help branch prediction for common tokens
    // - Range-for uses "const auto&" to avoid copying Token objects
    std::size_t format_to_impl(const Record& record, char* buf, std::size_t size) const {
        if (size == 0) [[unlikely]] return 0;
        
        char* ptr = buf;
        char* const end = buf + size - 1;  // Reserve for null terminator
        
        for (const auto& token : tokens) {
            if (ptr >= end) [[unlikely]] break;
            
            // High-frequency tokens first (Literal, Message, Tag, Time)
            switch (token.type) {
                case TokenType::Literal: [[likely]]
                    ptr += copy_to(ptr, end, token.literal);
                    break;
                case TokenType::Message: [[likely]]
                    ptr += copy_to(ptr, end, record.message);
                    break;
                case TokenType::Tag: [[likely]]
                    ptr += copy_to(ptr, end, record.tag);
                    break;
                case TokenType::Time:
                    ptr += format_timestamp_to(record.timestamp, ptr, end - ptr);
                    break;
                case TokenType::Time6:
                    ptr += format_timestamp_micros_to(record.timestamp, ptr, end - ptr);
                    break;
                case TokenType::Level:
                    ptr += copy_to(ptr, end, level_name(record.level));
                    break;
                case TokenType::LevelFull:
                    ptr += copy_to(ptr, end, level_full_name(record.level));
                    break;
                case TokenType::Date:
                    ptr += format_date_to(record.timestamp, ptr, end - ptr);
                    break;
                case TokenType::Pid:
                    ptr += uint_to_str(record.pid, ptr, end);
                    break;
                case TokenType::Tid:
                    ptr += uint_to_str(record.tid, ptr, end);
                    break;
                case TokenType::TidStar:
                    ptr += uint_to_str(record.tid, ptr, end);
                    if (record.is_main_thread() && ptr < end) *ptr++ = '*';
                    break;
                case TokenType::File:
                    ptr += copy_to(ptr, end, extract_filename(record.location.file_name()));
                    break;
                case TokenType::Path:
                    ptr += copy_to(ptr, end, record.location.file_name());
                    break;
                case TokenType::Line:
                    ptr += uint_to_str(record.location.line(), ptr, end);
                    break;
                case TokenType::Func:
                    ptr += copy_to(ptr, end, record.location.function_name());
                    break;
                case TokenType::Newline:
                    if (ptr < end) *ptr++ = '\n';
                    break;
            }
        }
        
        *ptr = '\0';
        return static_cast<std::size_t>(ptr - buf);
    }
    
    // format() uses thread_local buffer to avoid heap allocation
    // Falls back to dynamic allocation only when message exceeds buffer size
    std::string format(const Record& record) const {
        // Thread-local buffer: avoids allocation per call
        // 1KB covers most log lines with comfortable margin
        constexpr std::size_t kTlsBufferSize = 1024;
        
        // Estimated header overhead (excluding message and tag):
        // time(~25) + level(~3) + pid/tid(~25) + file/line/func(~80) + literals(~20) + margin
        constexpr std::size_t kHeaderOverhead = 200;
        
        thread_local std::array<char, kTlsBufferSize> tls_buffer;
        
        // Estimate total size needed
        std::size_t estimated = kHeaderOverhead + record.message.size() + record.tag.size();
        
        if (estimated < kTlsBufferSize) {
            // Fast path: use TLS buffer
            std::size_t len = format_to_impl(record, tls_buffer.data(), tls_buffer.size());
            return std::string(tls_buffer.data(), len);
        } else {
            // Slow path: allocate exact size needed
            std::string result;
            result.resize(estimated + 128);  // Extra margin
            std::size_t len = format_to_impl(record, result.data(), result.size());
            result.resize(len);
            return result;
        }
    }
    
    std::size_t format_to(const Record& record, char* buffer, std::size_t size) const {
        return format_to_impl(record, buffer, size);
    }
    
private:
    // Fast copy with bounds checking, returns bytes copied
    static std::size_t copy_to(char* dst, const char* end, std::string_view src) {
        std::size_t avail = static_cast<std::size_t>(end - dst);
        std::size_t len = std::min(src.size(), avail);
        std::memcpy(dst, src.data(), len);
        return len;
    }
    
    // Fast uint64 to string, returns bytes written
    static std::size_t uint_to_str(std::uint64_t value, char* dst, const char* end) {
        std::size_t avail = static_cast<std::size_t>(end - dst);
        if (avail == 0) return 0;
        auto [ptr, ec] = std::to_chars(dst, dst + avail, value);
        return static_cast<std::size_t>(ptr - dst);
    }
    
    // Timestamp formatting directly to buffer
    static std::size_t format_timestamp_to(const Timestamp& tv, char* buf, std::size_t size) {
        if (size < 24) {
            auto s = format_timestamp(tv);
            std::size_t len = std::min(s.size(), size);
            std::memcpy(buf, s.data(), len);
            return len;
        }
        
        std::time_t sec = static_cast<std::time_t>(tv.tv_sec);
        std::tm tm_buf;
#ifdef _WIN32
        localtime_s(&tm_buf, &sec);
#else
        localtime_r(&sec, &tm_buf);
#endif
        // Format: YYYY-MM-DD HH:MM:SS.mmm (23 chars)
        int written = std::snprintf(buf, size, 
            "%04d-%02d-%02d %02d:%02d:%02d.%03d",
            tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
            tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
            static_cast<int>(tv.tv_usec / 1000));
        return written > 0 ? static_cast<std::size_t>(written) : 0;
    }
    
    static std::size_t format_timestamp_micros_to(const Timestamp& tv, char* buf, std::size_t size) {
        if (size < 27) {
            auto s = format_timestamp_micros(tv);
            std::size_t len = std::min(s.size(), size);
            std::memcpy(buf, s.data(), len);
            return len;
        }
        
        std::time_t sec = static_cast<std::time_t>(tv.tv_sec);
        std::tm tm_buf;
#ifdef _WIN32
        localtime_s(&tm_buf, &sec);
#else
        localtime_r(&sec, &tm_buf);
#endif
        // Format: YYYY-MM-DD HH:MM:SS.uuuuuu (26 chars)
        int written = std::snprintf(buf, size,
            "%04d-%02d-%02d %02d:%02d:%02d.%06d",
            tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
            tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
            static_cast<int>(tv.tv_usec));
        return written > 0 ? static_cast<std::size_t>(written) : 0;
    }
    
    static std::size_t format_date_to(const Timestamp& tv, char* buf, std::size_t size) {
        if (size < 11) {
            auto s = format_date(tv);
            std::size_t len = std::min(s.size(), size);
            std::memcpy(buf, s.data(), len);
            return len;
        }
        
        std::time_t sec = static_cast<std::time_t>(tv.tv_sec);
        std::tm tm_buf;
#ifdef _WIN32
        localtime_s(&tm_buf, &sec);
#else
        localtime_r(&sec, &tm_buf);
#endif
        // Format: YYYY-MM-DD (10 chars)
        int written = std::snprintf(buf, size, "%04d-%02d-%02d",
            tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday);
        return written > 0 ? static_cast<std::size_t>(written) : 0;
    }
};

// ============================================================================
// Formatter Public API
// ============================================================================

Formatter::Formatter() : impl_(std::make_unique<Impl>()) {
    impl_->parse_pattern(kDefaultPattern);
}

Formatter::Formatter(std::string_view pattern) : impl_(std::make_unique<Impl>()) {
    impl_->parse_pattern(pattern);
}

Formatter::~Formatter() = default;

Formatter::Formatter(Formatter&&) noexcept = default;
Formatter& Formatter::operator=(Formatter&&) noexcept = default;

void Formatter::set_pattern(std::string_view pattern) {
    impl_->parse_pattern(pattern);
}

std::string_view Formatter::pattern() const noexcept {
    return impl_->pattern;
}

std::string Formatter::format(const Record& record) const {
    return impl_->format(record);
}

std::size_t Formatter::format_to(const Record& record, char* buffer, std::size_t size) const {
    return impl_->format_to(record, buffer, size);
}

} // namespace logln
