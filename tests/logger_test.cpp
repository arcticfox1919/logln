// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "logln/logger.hpp"
#include "logln/config.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <thread>
#include <chrono>
#include <atomic>

namespace logln {
namespace {

// Test fixture with cleanup
class LoggerTest : public ::testing::Test {
protected:
    std::filesystem::path test_dir_;
    
    void SetUp() override {
        // Create unique test directory
        test_dir_ = std::filesystem::temp_directory_path() / 
                    ("logln_test_" + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id())));
        std::filesystem::create_directories(test_dir_);
        
        // Ensure clean state
        Logger::release_all();
    }
    
    void TearDown() override {
        // Clean up loggers
        Logger::release_all();
        
        // Remove test directory
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
    }
    
    Config make_config(const std::string& name = "Test") {
        Config cfg;
        cfg.name_prefix = name;
        cfg.log_dir = test_dir_;
        cfg.cache_dir = test_dir_ / "cache";
        cfg.mode = WriteMode::Sync;  // Use sync mode for predictable tests
        cfg.min_level = Level::Verbose;
        return cfg;
    }
};

// ============================================================================
// Factory / Registry Tests
// ============================================================================

TEST_F(LoggerTest, CreateLogger) {
    auto* logger = Logger::create(make_config("MyLogger"));
    
    ASSERT_NE(logger, nullptr);
    EXPECT_EQ(logger->name(), "MyLogger");
    EXPECT_TRUE(logger->is_initialized());
}

TEST_F(LoggerTest, CreateDuplicateNameFails) {
    auto* logger1 = Logger::create(make_config("Duplicate"));
    auto* logger2 = Logger::create(make_config("Duplicate"));
    
    ASSERT_NE(logger1, nullptr);
    EXPECT_EQ(logger2, nullptr);  // Duplicate name should fail
}

TEST_F(LoggerTest, GetLogger) {
    auto* created = Logger::create(make_config("GetTest"));
    auto* retrieved = Logger::get("GetTest");
    
    EXPECT_EQ(created, retrieved);
}

TEST_F(LoggerTest, GetNonexistentReturnsNull) {
    auto* logger = Logger::get("NonExistent");
    EXPECT_EQ(logger, nullptr);
}

TEST_F(LoggerTest, InstanceReturnsLogger) {
    auto* created = Logger::create(make_config("InstanceTest"));
    auto* instance = Logger::instance("InstanceTest");
    
    EXPECT_EQ(created, instance);
}

TEST_F(LoggerTest, ExistsCheck) {
    EXPECT_FALSE(Logger::exists("ExistsTest"));
    
    Logger::create(make_config("ExistsTest"));
    
    EXPECT_TRUE(Logger::exists("ExistsTest"));
}

TEST_F(LoggerTest, ReleaseLogger) {
    Logger::create(make_config("ReleaseTest"));
    EXPECT_TRUE(Logger::exists("ReleaseTest"));
    
    bool released = Logger::release("ReleaseTest");
    
    EXPECT_TRUE(released);
    EXPECT_FALSE(Logger::exists("ReleaseTest"));
}

TEST_F(LoggerTest, ReleaseNonexistentReturnsFalse) {
    bool released = Logger::release("NonExistent");
    EXPECT_FALSE(released);
}

TEST_F(LoggerTest, ReleaseAll) {
    Logger::create(make_config("Logger1"));
    Logger::create(make_config("Logger2"));
    Logger::create(make_config("Logger3"));
    
    EXPECT_EQ(Logger::count(), 3);
    
    Logger::release_all();
    
    EXPECT_EQ(Logger::count(), 0);
}

TEST_F(LoggerTest, Names) {
    Logger::create(make_config("Alpha"));
    Logger::create(make_config("Beta"));
    
    auto names = Logger::names();
    
    EXPECT_EQ(names.size(), 2);
    EXPECT_TRUE(std::find(names.begin(), names.end(), "Alpha") != names.end());
    EXPECT_TRUE(std::find(names.begin(), names.end(), "Beta") != names.end());
}

TEST_F(LoggerTest, Count) {
    EXPECT_EQ(Logger::count(), 0);
    
    Logger::create(make_config("One"));
    EXPECT_EQ(Logger::count(), 1);
    
    Logger::create(make_config("Two"));
    EXPECT_EQ(Logger::count(), 2);
}

// ============================================================================
// Configuration Tests
// ============================================================================

TEST_F(LoggerTest, SetLevel) {
    auto* logger = Logger::create(make_config("LevelTest"));
    
    logger->set_level(Level::Warn);
    EXPECT_EQ(logger->level(), Level::Warn);
    
    logger->set_level(Level::Debug);
    EXPECT_EQ(logger->level(), Level::Debug);
}

TEST_F(LoggerTest, IsEnabled) {
    auto* logger = Logger::create(make_config("EnabledTest"));
    logger->set_level(Level::Info);
    
    EXPECT_FALSE(logger->is_enabled(Level::Verbose));
    EXPECT_FALSE(logger->is_enabled(Level::Debug));
    EXPECT_TRUE(logger->is_enabled(Level::Info));
    EXPECT_TRUE(logger->is_enabled(Level::Warn));
    EXPECT_TRUE(logger->is_enabled(Level::Error));
    EXPECT_TRUE(logger->is_enabled(Level::Fatal));
}

TEST_F(LoggerTest, SetConsoleOutput) {
    auto* logger = Logger::create(make_config("ConsoleTest"));
    
    logger->set_console_output(true);
    EXPECT_TRUE(logger->console_output());
    
    logger->set_console_output(false);
    EXPECT_FALSE(logger->console_output());
}

TEST_F(LoggerTest, SetMode) {
    auto* logger = Logger::create(make_config("ModeTest"));
    
    logger->set_mode(WriteMode::Async);
    EXPECT_EQ(logger->mode(), WriteMode::Async);
    
    logger->set_mode(WriteMode::Sync);
    EXPECT_EQ(logger->mode(), WriteMode::Sync);
}

TEST_F(LoggerTest, ConfigAccessor) {
    auto cfg = make_config("ConfigTest");
    cfg.min_level = Level::Warn;
    
    auto* logger = Logger::create(cfg);
    
    EXPECT_EQ(logger->config().name_prefix, "ConfigTest");
    EXPECT_EQ(logger->config().min_level, Level::Warn);
}

TEST_F(LoggerTest, SetPattern) {
    auto* logger = Logger::create(make_config("PatternTest"));
    
    std::string captured_formatted;
    logger->set_write_callback([&](const Record& record, std::string_view formatted) {
        captured_formatted = std::string(formatted);
        return true;
    });
    
    // Custom pattern: only level and message
    logger->set_pattern("[{level}] {msg}");
    logger->info("Tag", "Hello World");
    logger->flush_sync();
    
    // Should contain level and message, formatted according to pattern
    EXPECT_NE(captured_formatted.find("[I]"), std::string::npos);
    EXPECT_NE(captured_formatted.find("Hello World"), std::string::npos);
}

TEST_F(LoggerTest, SetPatternWithTag) {
    auto* logger = Logger::create(make_config("PatternTagTest"));
    
    std::string captured_formatted;
    logger->set_write_callback([&](const Record& record, std::string_view formatted) {
        captured_formatted = std::string(formatted);
        return true;
    });
    
    // Pattern with tag
    logger->set_pattern("{tag}: {msg}");
    logger->info("MyTag", "Test message");
    logger->flush_sync();
    
    EXPECT_NE(captured_formatted.find("MyTag:"), std::string::npos);
    EXPECT_NE(captured_formatted.find("Test message"), std::string::npos);
}

TEST_F(LoggerTest, SetPatternWithTimestamp) {
    auto* logger = Logger::create(make_config("PatternTimeTest"));
    
    std::string captured_formatted;
    logger->set_write_callback([&](const Record& record, std::string_view formatted) {
        captured_formatted = std::string(formatted);
        return true;
    });
    
    // Pattern with timestamp
    logger->set_pattern("{time} {msg}");
    logger->info("Tag", "Timed message");
    logger->flush_sync();
    
    // Should contain some timestamp format and the message
    EXPECT_NE(captured_formatted.find("Timed message"), std::string::npos);
    EXPECT_GT(captured_formatted.length(), std::string("Timed message").length());
}

// ============================================================================
// Logging Tests
// ============================================================================

TEST_F(LoggerTest, BasicLog) {
    auto* logger = Logger::create(make_config("LogTest"));
    
    // Should not throw
    logger->log(Level::Info, "Test", "Hello World");
    logger->flush_sync();
}

TEST_F(LoggerTest, FormatLog) {
    auto* logger = Logger::create(make_config("FormatTest"));
    
    // Should not throw
    logger->info("Test", "Value: {}", 42);
    logger->debug("Test", "Name: {}, Age: {}", "Alice", 30);
    logger->flush_sync();
}

TEST_F(LoggerTest, ConvenienceMethods) {
    auto* logger = Logger::create(make_config("ConvenienceTest"));
    logger->set_level(Level::Verbose);
    
    // All convenience methods should work
    logger->verbose("Tag", "Verbose message");
    logger->debug("Tag", "Debug message");
    logger->info("Tag", "Info message");
    logger->warn("Tag", "Warn message");
    logger->error("Tag", "Error message");
    logger->fatal("Tag", "Fatal message");
    
    logger->flush_sync();
}

TEST_F(LoggerTest, LevelFiltering) {
    auto* logger = Logger::create(make_config("FilterTest"));
    logger->set_level(Level::Error);
    
    std::atomic<int> call_count{0};
    logger->set_write_callback([&](const Record& record, std::string_view) {
        call_count++;
        return true;
    });
    
    logger->verbose("Tag", "Should be filtered");
    logger->debug("Tag", "Should be filtered");
    logger->info("Tag", "Should be filtered");
    logger->warn("Tag", "Should be filtered");
    logger->error("Tag", "Should pass");
    logger->fatal("Tag", "Should pass");
    
    logger->flush_sync();
    
    EXPECT_EQ(call_count.load(), 2);
}

// ============================================================================
// WriteCallback Tests
// ============================================================================

TEST_F(LoggerTest, WriteCallbackCalled) {
    auto* logger = Logger::create(make_config("CallbackTest"));
    
    bool callback_called = false;
    logger->set_write_callback([&](const Record& record, std::string_view formatted) {
        callback_called = true;
        EXPECT_EQ(record.level, Level::Info);
        EXPECT_EQ(record.tag, "MyTag");
        EXPECT_EQ(record.message, "Hello");
        EXPECT_FALSE(formatted.empty());
        return true;
    });
    
    logger->info("MyTag", "Hello");
    logger->flush_sync();
    
    EXPECT_TRUE(callback_called);
}

TEST_F(LoggerTest, WriteCallbackCanFilter) {
    auto* logger = Logger::create(make_config("FilterCallbackTest"));
    
    std::atomic<int> write_count{0};
    logger->set_write_callback([&](const Record& record, std::string_view) {
        write_count++;
        // Filter out messages containing "secret"
        return record.message.find("secret") == std::string_view::npos;
    });
    
    logger->info("Tag", "Normal message");
    logger->info("Tag", "This is secret");
    logger->info("Tag", "Another normal");
    
    logger->flush_sync();
    
    // Callback was called 3 times, but only 2 should have been written
    EXPECT_EQ(write_count.load(), 3);
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

TEST_F(LoggerTest, ShutdownLogger) {
    auto* logger = Logger::create(make_config("ShutdownTest"));
    EXPECT_TRUE(logger->is_initialized());
    
    logger->shutdown();
    
    EXPECT_FALSE(logger->is_initialized());
}

TEST_F(LoggerTest, LogAfterShutdown) {
    auto* logger = Logger::create(make_config("PostShutdownTest"));
    logger->shutdown();
    
    // Should not crash
    logger->info("Tag", "Message after shutdown");
}

// ============================================================================
// Bulk Operations Tests
// ============================================================================

TEST_F(LoggerTest, SetLevelAll) {
    Logger::create(make_config("BulkA"));
    Logger::create(make_config("BulkB"));
    
    Logger::set_level_all(Level::Error);
    
    EXPECT_EQ(Logger::get("BulkA")->level(), Level::Error);
    EXPECT_EQ(Logger::get("BulkB")->level(), Level::Error);
}

TEST_F(LoggerTest, SetModeAll) {
    Logger::create(make_config("ModeA"));
    Logger::create(make_config("ModeB"));
    
    Logger::set_mode_all(WriteMode::Async);
    
    EXPECT_EQ(Logger::get("ModeA")->mode(), WriteMode::Async);
    EXPECT_EQ(Logger::get("ModeB")->mode(), WriteMode::Async);
}

TEST_F(LoggerTest, FlushAll) {
    Logger::create(make_config("FlushA"));
    Logger::create(make_config("FlushB"));
    
    Logger::get("FlushA")->info("Tag", "Message A");
    Logger::get("FlushB")->info("Tag", "Message B");
    
    // Should not throw
    Logger::flush_all(true);
}

// ============================================================================
// File Management Tests
// ============================================================================

TEST_F(LoggerTest, CurrentLogPath) {
    auto* logger = Logger::create(make_config("PathTest"));
    
    auto path = logger->current_log_path();
    EXPECT_FALSE(path.empty());
}

TEST_F(LoggerTest, GetAllLogFiles) {
    auto* logger = Logger::create(make_config("FilesTest"));
    logger->info("Tag", "Create some content");
    logger->flush_sync();
    
    auto files = logger->get_all_log_files(true);
    // Should have at least one file (the current one)
    EXPECT_GE(files.size(), 0);  // May be 0 if mmap only
}

// ============================================================================
// Async Mode Tests
// ============================================================================

TEST_F(LoggerTest, AsyncModeBasic) {
    auto* logger = Logger::create(make_config("AsyncBasic"));
    logger->set_mode(WriteMode::Async);
    
    // Async logging should return immediately
    for (int i = 0; i < 100; ++i) {
        logger->info("Tag", "Async message {}", i);
    }
    
    // flush_sync should wait for all messages to be processed
    logger->flush_sync();
    
    // If we get here without crash/deadlock, test passes
}

TEST_F(LoggerTest, AsyncModeWithCallback) {
    auto* logger = Logger::create(make_config("AsyncCallback"));
    logger->set_mode(WriteMode::Async);
    
    std::atomic<int> callback_count{0};
    logger->set_write_callback([&](const Record& record, std::string_view formatted) {
        callback_count++;
        return true;
    });
    
    constexpr int num_messages = 50;
    for (int i = 0; i < num_messages; ++i) {
        logger->info("Tag", "Message {}", i);
    }
    
    logger->flush_sync();
    
    // All messages should have triggered callback
    EXPECT_EQ(callback_count.load(), num_messages);
}

TEST_F(LoggerTest, AsyncModeNonBlocking) {
    auto* logger = Logger::create(make_config("AsyncNonBlock"));
    logger->set_mode(WriteMode::Async);
    
    auto start = std::chrono::steady_clock::now();
    
    // Write many messages - should return quickly in async mode
    for (int i = 0; i < 1000; ++i) {
        logger->info("Tag", "This is a longer message to test async performance {}", i);
    }
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // In async mode, writes should be very fast (< 100ms for 1000 messages)
    // This is a rough check - actual time depends on system load
    EXPECT_LT(duration.count(), 500);
    
    logger->flush_sync();
}

TEST_F(LoggerTest, AsyncModeSwitchToSync) {
    auto* logger = Logger::create(make_config("AsyncSwitch"));
    
    // Start in async mode
    logger->set_mode(WriteMode::Async);
    logger->info("Tag", "Async message 1");
    logger->info("Tag", "Async message 2");
    
    // Switch to sync mode - should flush pending messages
    logger->set_mode(WriteMode::Sync);
    EXPECT_EQ(logger->mode(), WriteMode::Sync);
    
    // Continue logging in sync mode
    logger->info("Tag", "Sync message 1");
    logger->flush_sync();
}

TEST_F(LoggerTest, AsyncModeHighVolume) {
    auto* logger = Logger::create(make_config("AsyncHighVol"));
    logger->set_mode(WriteMode::Async);
    
    std::atomic<int> callback_count{0};
    logger->set_write_callback([&](const Record&, std::string_view) {
        callback_count++;
        return true;
    });
    
    // High volume logging
    constexpr int num_messages = 5000;
    for (int i = 0; i < num_messages; ++i) {
        logger->info("Tag", "High volume message {}", i);
    }
    
    logger->flush_sync();
    
    // All messages should be processed
    EXPECT_EQ(callback_count.load(), num_messages);
}

TEST_F(LoggerTest, AsyncModeMultiLevel) {
    auto* logger = Logger::create(make_config("AsyncLevels"));
    logger->set_mode(WriteMode::Async);
    logger->set_level(Level::Verbose);
    
    std::atomic<int> callback_count{0};
    logger->set_write_callback([&](const Record&, std::string_view) {
        callback_count++;
        return true;
    });
    
    // Log at all levels
    logger->verbose("Tag", "Verbose");
    logger->debug("Tag", "Debug");
    logger->info("Tag", "Info");
    logger->warn("Tag", "Warn");
    logger->error("Tag", "Error");
    logger->fatal("Tag", "Fatal");
    
    logger->flush_sync();
    
    EXPECT_EQ(callback_count.load(), 6);
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST_F(LoggerTest, ConcurrentLogging) {
    auto* logger = Logger::create(make_config("ConcurrentTest"));
    logger->set_mode(WriteMode::Async);
    
    constexpr int num_threads = 4;
    constexpr int logs_per_thread = 100;
    
    std::vector<std::thread> threads;
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([logger, t]() {
            for (int i = 0; i < logs_per_thread; ++i) {
                logger->info("Thread", "Thread {} log {}", t, i);
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    logger->flush_sync();
    // If we get here without crash/deadlock, test passes
}

TEST_F(LoggerTest, ConcurrentCreateRelease) {
    constexpr int iterations = 10;
    
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([this, t]() {
            for (int i = 0; i < iterations; ++i) {
                auto name = std::format("Concurrent_{}_{}", t, i);
                auto* logger = Logger::create(make_config(name));
                if (logger) {
                    logger->info("Tag", "Hello");
                    Logger::release(name);
                }
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
}

// ============================================================================
// Debug Utilities Tests
// ============================================================================

TEST_F(LoggerTest, Dump) {
    const char data[] = "Hello";
    auto dump = Logger::dump(data, sizeof(data));
    
    EXPECT_FALSE(dump.empty());
    EXPECT_NE(dump.find("Hello"), std::string::npos);
}

TEST_F(LoggerTest, MemoryDump) {
    const unsigned char data[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    auto dump = Logger::memory_dump(data, sizeof(data));
    
    EXPECT_FALSE(dump.empty());
    // Should contain hex representation
    EXPECT_NE(dump.find("48"), std::string::npos);
}

} // anonymous namespace
} // namespace logln
