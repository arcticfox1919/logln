// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "logln/formatter.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <thread>

namespace logln {
namespace {

// Helper to create a test record
Record make_test_record(Level level = Level::Info,
                        std::string_view tag = "TestTag",
                        std::string_view message = "Test message",
                        std::source_location loc = std::source_location::current()) {
    Record record;
    record.level = level;
    record.tag = tag;
    record.message = message;
    record.timestamp = Timestamp::now();
    record.pid = 12345;
    record.tid = 67890;
    record.main_tid = 67890;  // Same as tid = main thread
    record.location = loc;
    return record;
}

// ============================================================================
// Construction Tests
// ============================================================================

TEST(FormatterTest, DefaultConstruction) {
    Formatter formatter;
    // Default pattern should be set
    EXPECT_FALSE(formatter.pattern().empty());
}

TEST(FormatterTest, ConstructWithPattern) {
    Formatter formatter("{level} {msg}");
    EXPECT_EQ(formatter.pattern(), "{level} {msg}");
}

TEST(FormatterTest, MoveConstruction) {
    Formatter original("{level} {msg}");
    Formatter moved(std::move(original));
    EXPECT_EQ(moved.pattern(), "{level} {msg}");
}

TEST(FormatterTest, MoveAssignment) {
    Formatter original("{level} {msg}");
    Formatter target("{time}");
    target = std::move(original);
    EXPECT_EQ(target.pattern(), "{level} {msg}");
}

// ============================================================================
// Pattern Setting Tests
// ============================================================================

TEST(FormatterTest, SetPattern) {
    Formatter formatter;
    formatter.set_pattern("{tag}: {msg}");
    EXPECT_EQ(formatter.pattern(), "{tag}: {msg}");
}

TEST(FormatterTest, SetEmptyPattern) {
    Formatter formatter("{level}");
    formatter.set_pattern("");
    EXPECT_EQ(formatter.pattern(), "");
}

// ============================================================================
// Level Token Tests
// ============================================================================

TEST(FormatterTest, LevelTokenShort) {
    Formatter formatter("{level}");
    
    EXPECT_EQ(formatter.format(make_test_record(Level::Verbose)), "V");
    EXPECT_EQ(formatter.format(make_test_record(Level::Debug)), "D");
    EXPECT_EQ(formatter.format(make_test_record(Level::Info)), "I");
    EXPECT_EQ(formatter.format(make_test_record(Level::Warn)), "W");
    EXPECT_EQ(formatter.format(make_test_record(Level::Error)), "E");
    EXPECT_EQ(formatter.format(make_test_record(Level::Fatal)), "F");
}

TEST(FormatterTest, LevelTokenFull) {
    Formatter formatter("{Level}");
    
    EXPECT_EQ(formatter.format(make_test_record(Level::Verbose)), "VERBOSE");
    EXPECT_EQ(formatter.format(make_test_record(Level::Debug)), "DEBUG");
    EXPECT_EQ(formatter.format(make_test_record(Level::Info)), "INFO");
    EXPECT_EQ(formatter.format(make_test_record(Level::Warn)), "WARN");
    EXPECT_EQ(formatter.format(make_test_record(Level::Error)), "ERROR");
    EXPECT_EQ(formatter.format(make_test_record(Level::Fatal)), "FATAL");
}

// ============================================================================
// Message and Tag Token Tests
// ============================================================================

TEST(FormatterTest, MessageToken) {
    Formatter formatter("{msg}");
    auto record = make_test_record(Level::Info, "tag", "Hello, World!");
    EXPECT_EQ(formatter.format(record), "Hello, World!");
}

TEST(FormatterTest, TagToken) {
    Formatter formatter("{tag}");
    auto record = make_test_record(Level::Info, "MyComponent", "msg");
    EXPECT_EQ(formatter.format(record), "MyComponent");
}

TEST(FormatterTest, EmptyMessage) {
    Formatter formatter("[{msg}]");
    auto record = make_test_record(Level::Info, "tag", "");
    EXPECT_EQ(formatter.format(record), "[]");
}

TEST(FormatterTest, EmptyTag) {
    Formatter formatter("[{tag}]");
    auto record = make_test_record(Level::Info, "", "msg");
    EXPECT_EQ(formatter.format(record), "[]");
}

// ============================================================================
// Process/Thread ID Token Tests
// ============================================================================

TEST(FormatterTest, PidToken) {
    Formatter formatter("{pid}");
    auto record = make_test_record();
    record.pid = 99999;
    EXPECT_EQ(formatter.format(record), "99999");
}

TEST(FormatterTest, TidToken) {
    Formatter formatter("{tid}");
    auto record = make_test_record();
    record.tid = 11111;
    EXPECT_EQ(formatter.format(record), "11111");
}

TEST(FormatterTest, TidStarTokenMainThread) {
    Formatter formatter("{tid*}");
    auto record = make_test_record();
    record.tid = 12345;
    record.main_tid = 12345;  // Same = main thread
    EXPECT_EQ(formatter.format(record), "12345*");
}

TEST(FormatterTest, TidStarTokenNonMainThread) {
    Formatter formatter("{tid*}");
    auto record = make_test_record();
    record.tid = 12345;
    record.main_tid = 99999;  // Different = not main thread
    EXPECT_EQ(formatter.format(record), "12345");
}

// ============================================================================
// Time Token Tests
// ============================================================================

TEST(FormatterTest, TimeTokenFormat) {
    Formatter formatter("{time}");
    auto record = make_test_record();
    auto result = formatter.format(record);
    
    // Should contain date and time components
    // Format: YYYY-MM-DD HH:MM:SS.mmm (23 chars)
    EXPECT_GE(result.size(), 19);  // At least YYYY-MM-DD HH:MM:SS
}

TEST(FormatterTest, Time6TokenFormat) {
    Formatter formatter("{time6}");
    auto record = make_test_record();
    auto result = formatter.format(record);
    
    // Format: YYYY-MM-DD HH:MM:SS.uuuuuu (26 chars)
    EXPECT_GE(result.size(), 19);
}

TEST(FormatterTest, DateTokenFormat) {
    Formatter formatter("{date}");
    auto record = make_test_record();
    auto result = formatter.format(record);
    
    // Format: YYYY-MM-DD (10 chars)
    EXPECT_EQ(result.size(), 10);
    EXPECT_EQ(result[4], '-');
    EXPECT_EQ(result[7], '-');
}

// ============================================================================
// Source Location Token Tests
// ============================================================================

TEST(FormatterTest, FileToken) {
    Formatter formatter("{file}");
    auto record = make_test_record();
    auto result = formatter.format(record);
    // Should extract filename from __FILE__
    EXPECT_FALSE(result.empty());
}

TEST(FormatterTest, PathToken) {
    Formatter formatter("{path}");
    auto record = make_test_record();
    auto result = formatter.format(record);
    // Should contain full path
    EXPECT_FALSE(result.empty());
}

TEST(FormatterTest, LineToken) {
    Formatter formatter("{line}");
    auto record = make_test_record();
    auto result = formatter.format(record);
    // Line number should be positive
    EXPECT_FALSE(result.empty());
    int line = std::stoi(result);
    EXPECT_GT(line, 0);
}

TEST(FormatterTest, FuncToken) {
    Formatter formatter("{func}");
    auto record = make_test_record();
    auto result = formatter.format(record);
    // Function name
    EXPECT_FALSE(result.empty());
}

// ============================================================================
// Newline Token Tests
// ============================================================================

TEST(FormatterTest, NewlineToken) {
    Formatter formatter("{msg}{n}");
    auto record = make_test_record(Level::Info, "tag", "Hello");
    EXPECT_EQ(formatter.format(record), "Hello\n");
}

TEST(FormatterTest, MultipleNewlines) {
    Formatter formatter("{n}{msg}{n}{n}");
    auto record = make_test_record(Level::Info, "tag", "Hi");
    EXPECT_EQ(formatter.format(record), "\nHi\n\n");
}

// ============================================================================
// Literal Text Tests
// ============================================================================

TEST(FormatterTest, LiteralOnly) {
    Formatter formatter("Hello World");
    auto record = make_test_record();
    EXPECT_EQ(formatter.format(record), "Hello World");
}

TEST(FormatterTest, LiteralWithTokens) {
    Formatter formatter("[{level}] {msg}");
    auto record = make_test_record(Level::Info, "tag", "Test");
    EXPECT_EQ(formatter.format(record), "[I] Test");
}

TEST(FormatterTest, LiteralBetweenTokens) {
    Formatter formatter("{level} - {tag} - {msg}");
    auto record = make_test_record(Level::Warn, "App", "Warning!");
    EXPECT_EQ(formatter.format(record), "W - App - Warning!");
}

// ============================================================================
// Unknown Token Tests
// ============================================================================

TEST(FormatterTest, UnknownTokenTreatedAsLiteral) {
    Formatter formatter("{unknown}");
    auto record = make_test_record();
    EXPECT_EQ(formatter.format(record), "{unknown}");
}

TEST(FormatterTest, MixedKnownUnknownTokens) {
    Formatter formatter("{level} {foo} {msg}");
    auto record = make_test_record(Level::Error, "tag", "Error!");
    EXPECT_EQ(formatter.format(record), "E {foo} Error!");
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST(FormatterTest, UnclosedBrace) {
    Formatter formatter("{level {msg}");
    auto record = make_test_record(Level::Info, "tag", "Test");
    // Unclosed brace should be treated as literal
    auto result = formatter.format(record);
    EXPECT_TRUE(result.find("{level") != std::string::npos || 
                result.find("Test") != std::string::npos);
}

TEST(FormatterTest, EmptyBraces) {
    Formatter formatter("{}");
    auto record = make_test_record();
    EXPECT_EQ(formatter.format(record), "{}");
}

TEST(FormatterTest, NestedBraces) {
    Formatter formatter("{{level}}");
    auto record = make_test_record(Level::Info);
    // First { is literal until }, then {level} is token, then } is error
    // Behavior may vary - just ensure no crash
    auto result = formatter.format(record);
    EXPECT_FALSE(result.empty());
}

TEST(FormatterTest, ConsecutiveTokens) {
    Formatter formatter("{level}{tag}{msg}");
    auto record = make_test_record(Level::Debug, "T", "M");
    EXPECT_EQ(formatter.format(record), "DTM");
}

// ============================================================================
// format_to Tests
// ============================================================================

TEST(FormatterTest, FormatToSufficientBuffer) {
    Formatter formatter("{level} {msg}");
    auto record = make_test_record(Level::Info, "tag", "Hello");
    
    char buffer[100];
    auto len = formatter.format_to(record, buffer, sizeof(buffer));
    
    EXPECT_EQ(std::string(buffer), "I Hello");
    EXPECT_EQ(len, 7);
}

TEST(FormatterTest, FormatToSmallBuffer) {
    Formatter formatter("{msg}");
    auto record = make_test_record(Level::Info, "tag", "Hello World");
    
    char buffer[6];  // Only room for "Hello"
    auto len = formatter.format_to(record, buffer, sizeof(buffer));
    
    EXPECT_EQ(len, 5);
    EXPECT_EQ(std::string(buffer), "Hello");
}

TEST(FormatterTest, FormatToExactBuffer) {
    Formatter formatter("{msg}");
    auto record = make_test_record(Level::Info, "tag", "Hi");
    
    char buffer[3];  // "Hi" + null
    auto len = formatter.format_to(record, buffer, sizeof(buffer));
    
    EXPECT_EQ(len, 2);
    EXPECT_EQ(std::string(buffer), "Hi");
}

// ============================================================================
// Complex Pattern Tests
// ============================================================================

TEST(FormatterTest, RealisticPattern) {
    Formatter formatter("{time} [{level}] [{tag}] {file}:{line} {msg}{n}");
    auto record = make_test_record(Level::Info, "Network", "Connection established");
    
    auto result = formatter.format(record);
    EXPECT_TRUE(result.find("[I]") != std::string::npos);
    EXPECT_TRUE(result.find("[Network]") != std::string::npos);
    EXPECT_TRUE(result.find("Connection established") != std::string::npos);
    EXPECT_TRUE(result.back() == '\n');
}

TEST(FormatterTest, MinimalPattern) {
    Formatter formatter("{msg}");
    auto record = make_test_record(Level::Info, "", "Minimal");
    EXPECT_EQ(formatter.format(record), "Minimal");
}

TEST(FormatterTest, VerbosePattern) {
    Formatter formatter("{date} {time6} PID:{pid} TID:{tid*} [{Level}] {path}:{line} ({func}) [{tag}] {msg}{n}");
    auto record = make_test_record(Level::Warn, "MyClass", "Something happened");
    record.pid = 1234;
    record.tid = 5678;
    record.main_tid = 5678;
    
    auto result = formatter.format(record);
    EXPECT_TRUE(result.find("PID:1234") != std::string::npos);
    EXPECT_TRUE(result.find("TID:5678*") != std::string::npos);
    EXPECT_TRUE(result.find("[WARN]") != std::string::npos);
    EXPECT_TRUE(result.find("[MyClass]") != std::string::npos);
}

// ============================================================================
// Performance Sanity Tests
// ============================================================================

TEST(FormatterTest, FormatManyRecords) {
    Formatter formatter("{time} [{level}] {msg}{n}");
    auto record = make_test_record(Level::Info, "Perf", "Performance test message");
    
    // Just ensure it can format many records without issues
    for (int i = 0; i < 10000; ++i) {
        auto result = formatter.format(record);
        EXPECT_FALSE(result.empty());
    }
}

TEST(FormatterTest, LongMessage) {
    Formatter formatter("{msg}");
    
    std::string long_message(10000, 'x');
    auto record = make_test_record(Level::Info, "tag", long_message);
    
    auto result = formatter.format(record);
    EXPECT_EQ(result.size(), 10000);
}

}  // namespace
}  // namespace logln
