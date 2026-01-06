// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors
//
// Performance Benchmark Tests for Logln
//
// Tests various configurations:
// - No compression, no encryption (plain text)
// - With compression only
// - With encryption only  
// - With both compression and encryption
// - Sync vs Async mode comparison

#include "logln/logger.hpp"
#include "logln/config.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <chrono>
#include <thread>
#include <iostream>
#include <iomanip>
#include <vector>
#include <numeric>
#include <random>

namespace logln {
namespace {

// ============================================================================
// Benchmark Fixture
// ============================================================================

class BenchmarkTest : public ::testing::Test {
protected:
    std::filesystem::path test_dir_;
    
    void SetUp() override {
        test_dir_ = std::filesystem::temp_directory_path() / 
                    ("logln_bench_" + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id())));
        std::filesystem::create_directories(test_dir_);
        Logger::release_all();
    }
    
    void TearDown() override {
        Logger::release_all();
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
    }
    
    Config make_config(const std::string& name, 
                       bool compress = false, 
                       bool encrypt = false) {
        Config cfg;
        cfg.name_prefix = name;
        cfg.log_dir = test_dir_;
        cfg.cache_dir = test_dir_ / "cache";
        cfg.min_level = Level::Verbose;
        if (compress) {
            cfg.compression = Compression::Zstd;
        }
        if (encrypt) {
            // Use test server public key (64 hex chars = 32 bytes)
            cfg.pub_key = std::string(64, '4');
        }
        return cfg;
    }
    
    struct BenchmarkResult {
        std::string name;
        int num_iterations;
        int message_size;
        double total_time_ms;
        double ops_per_second;
        double mb_per_second;
        double avg_latency_us;
    };
    
    void print_result(const BenchmarkResult& result) {
        std::cout << std::left << std::setw(40) << result.name
                  << " | " << std::right << std::setw(10) << std::fixed << std::setprecision(0) 
                  << result.ops_per_second << " ops/s"
                  << " | " << std::setw(8) << std::setprecision(2) 
                  << result.mb_per_second << " MB/s"
                  << " | " << std::setw(8) << std::setprecision(2) 
                  << result.avg_latency_us << " us/op"
                  << std::endl;
    }
    
    BenchmarkResult run_benchmark(const std::string& name,
                                   Logger* logger,
                                   int num_iterations,
                                   int message_size) {
        // Prepare test message
        std::string message(message_size, 'X');
        
        // Warmup
        for (int i = 0; i < 100; ++i) {
            logger->info("Bench", "{}", message);
        }
        logger->flush_sync();
        
        // Actual benchmark
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < num_iterations; ++i) {
            logger->info("Bench", "{}", message);
        }
        logger->flush_sync();
        
        auto end = std::chrono::high_resolution_clock::now();
        
        double total_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double total_bytes = static_cast<double>(num_iterations) * message_size;
        
        BenchmarkResult result;
        result.name = name;
        result.num_iterations = num_iterations;
        result.message_size = message_size;
        result.total_time_ms = total_ms;
        result.ops_per_second = num_iterations / (total_ms / 1000.0);
        result.mb_per_second = (total_bytes / (1024.0 * 1024.0)) / (total_ms / 1000.0);
        result.avg_latency_us = (total_ms * 1000.0) / num_iterations;
        
        return result;
    }
};

// ============================================================================
// Sync Mode Benchmarks
// ============================================================================

TEST_F(BenchmarkTest, SyncMode_PlainText_SmallMessage) {
    auto cfg = make_config("SyncPlainSmall", false, false);
    cfg.mode = WriteMode::Sync;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Sync | Plain | 64B", logger, 10000, 64);
    print_result(result);
    
    // Basic sanity check - should be able to do at least 1000 ops/s
    EXPECT_GT(result.ops_per_second, 1000);
}

TEST_F(BenchmarkTest, SyncMode_PlainText_MediumMessage) {
    auto cfg = make_config("SyncPlainMedium", false, false);
    cfg.mode = WriteMode::Sync;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Sync | Plain | 256B", logger, 10000, 256);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 500);
}

TEST_F(BenchmarkTest, SyncMode_PlainText_LargeMessage) {
    auto cfg = make_config("SyncPlainLarge", false, false);
    cfg.mode = WriteMode::Sync;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Sync | Plain | 1KB", logger, 5000, 1024);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 100);
}

TEST_F(BenchmarkTest, SyncMode_Compressed_SmallMessage) {
    auto cfg = make_config("SyncCompSmall", true, false);
    cfg.mode = WriteMode::Sync;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Sync | Zstd | 64B", logger, 10000, 64);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 500);
}

TEST_F(BenchmarkTest, SyncMode_Compressed_LargeMessage) {
    auto cfg = make_config("SyncCompLarge", true, false);
    cfg.mode = WriteMode::Sync;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Sync | Zstd | 1KB", logger, 5000, 1024);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 100);
}

TEST_F(BenchmarkTest, SyncMode_Encrypted_SmallMessage) {
    auto cfg = make_config("SyncEncSmall", false, true);
    cfg.mode = WriteMode::Sync;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Sync | ChaCha20 | 64B", logger, 10000, 64);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 500);
}

TEST_F(BenchmarkTest, SyncMode_Encrypted_LargeMessage) {
    auto cfg = make_config("SyncEncLarge", false, true);
    cfg.mode = WriteMode::Sync;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Sync | ChaCha20 | 1KB", logger, 5000, 1024);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 100);
}

TEST_F(BenchmarkTest, SyncMode_CompressedEncrypted_SmallMessage) {
    auto cfg = make_config("SyncCompEncSmall", true, true);
    cfg.mode = WriteMode::Sync;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Sync | Zstd+ChaCha20 | 64B", logger, 10000, 64);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 300);
}

TEST_F(BenchmarkTest, SyncMode_CompressedEncrypted_LargeMessage) {
    auto cfg = make_config("SyncCompEncLarge", true, true);
    cfg.mode = WriteMode::Sync;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Sync | Zstd+ChaCha20 | 1KB", logger, 5000, 1024);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 50);
}

// ============================================================================
// Async Mode Benchmarks
// ============================================================================

TEST_F(BenchmarkTest, AsyncMode_PlainText_SmallMessage) {
    auto cfg = make_config("AsyncPlainSmall", false, false);
    cfg.mode = WriteMode::Async;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Async | Plain | 64B", logger, 50000, 64);
    print_result(result);
    
    // Async should be much faster
    EXPECT_GT(result.ops_per_second, 10000);
}

TEST_F(BenchmarkTest, AsyncMode_PlainText_MediumMessage) {
    auto cfg = make_config("AsyncPlainMedium", false, false);
    cfg.mode = WriteMode::Async;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Async | Plain | 256B", logger, 50000, 256);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 5000);
}

TEST_F(BenchmarkTest, AsyncMode_PlainText_LargeMessage) {
    auto cfg = make_config("AsyncPlainLarge", false, false);
    cfg.mode = WriteMode::Async;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Async | Plain | 1KB", logger, 20000, 1024);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 1000);
}

TEST_F(BenchmarkTest, AsyncMode_Compressed_SmallMessage) {
    auto cfg = make_config("AsyncCompSmall", true, false);
    cfg.mode = WriteMode::Async;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Async | Zstd | 64B", logger, 50000, 64);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 5000);
}

TEST_F(BenchmarkTest, AsyncMode_Compressed_LargeMessage) {
    auto cfg = make_config("AsyncCompLarge", true, false);
    cfg.mode = WriteMode::Async;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Async | Zstd | 1KB", logger, 20000, 1024);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 500);
}

TEST_F(BenchmarkTest, AsyncMode_Encrypted_SmallMessage) {
    auto cfg = make_config("AsyncEncSmall", false, true);
    cfg.mode = WriteMode::Async;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Async | ChaCha20 | 64B", logger, 50000, 64);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 5000);
}

TEST_F(BenchmarkTest, AsyncMode_Encrypted_LargeMessage) {
    auto cfg = make_config("AsyncEncLarge", false, true);
    cfg.mode = WriteMode::Async;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Async | ChaCha20 | 1KB", logger, 20000, 1024);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 500);
}

TEST_F(BenchmarkTest, AsyncMode_CompressedEncrypted_SmallMessage) {
    auto cfg = make_config("AsyncCompEncSmall", true, true);
    cfg.mode = WriteMode::Async;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Async | Zstd+ChaCha20 | 64B", logger, 50000, 64);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 3000);
}

TEST_F(BenchmarkTest, AsyncMode_CompressedEncrypted_LargeMessage) {
    auto cfg = make_config("AsyncCompEncLarge", true, true);
    cfg.mode = WriteMode::Async;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    auto result = run_benchmark("Async | Zstd+ChaCha20 | 1KB", logger, 20000, 1024);
    print_result(result);
    
    EXPECT_GT(result.ops_per_second, 300);
}

// ============================================================================
// Throughput Comparison Summary
// ============================================================================

TEST_F(BenchmarkTest, ThroughputSummary) {
    std::cout << "\n";
    std::cout << "========================================================================\n";
    std::cout << "                    LOGLN PERFORMANCE BENCHMARK SUMMARY\n";
    std::cout << "========================================================================\n";
    std::cout << std::left << std::setw(40) << "Configuration"
              << " | " << std::setw(14) << "Throughput"
              << " | " << std::setw(11) << "Bandwidth"
              << " | " << std::setw(11) << "Latency"
              << "\n";
    std::cout << "------------------------------------------------------------------------\n";
    
    constexpr int iterations = 10000;
    constexpr int msg_size = 128;
    
    std::vector<BenchmarkResult> results;
    
    // Sync mode tests
    {
        auto cfg = make_config("Summary_Sync_Plain", false, false);
        cfg.mode = WriteMode::Sync;
        auto* logger = Logger::create(cfg);
        results.push_back(run_benchmark("Sync  | Plain", logger, iterations, msg_size));
        Logger::release("Summary_Sync_Plain");
    }
    {
        auto cfg = make_config("Summary_Sync_Zstd", true, false);
        cfg.mode = WriteMode::Sync;
        auto* logger = Logger::create(cfg);
        results.push_back(run_benchmark("Sync  | Zstd", logger, iterations, msg_size));
        Logger::release("Summary_Sync_Zstd");
    }
    {
        auto cfg = make_config("Summary_Sync_ChaCha", false, true);
        cfg.mode = WriteMode::Sync;
        auto* logger = Logger::create(cfg);
        results.push_back(run_benchmark("Sync  | ChaCha20", logger, iterations, msg_size));
        Logger::release("Summary_Sync_ChaCha");
    }
    {
        auto cfg = make_config("Summary_Sync_Both", true, true);
        cfg.mode = WriteMode::Sync;
        auto* logger = Logger::create(cfg);
        results.push_back(run_benchmark("Sync  | Zstd+ChaCha20", logger, iterations, msg_size));
        Logger::release("Summary_Sync_Both");
    }
    
    std::cout << "------------------------------------------------------------------------\n";
    
    // Async mode tests
    {
        auto cfg = make_config("Summary_Async_Plain", false, false);
        cfg.mode = WriteMode::Async;
        auto* logger = Logger::create(cfg);
        results.push_back(run_benchmark("Async | Plain", logger, iterations * 3, msg_size));
        Logger::release("Summary_Async_Plain");
    }
    {
        auto cfg = make_config("Summary_Async_Zstd", true, false);
        cfg.mode = WriteMode::Async;
        auto* logger = Logger::create(cfg);
        results.push_back(run_benchmark("Async | Zstd", logger, iterations * 3, msg_size));
        Logger::release("Summary_Async_Zstd");
    }
    {
        auto cfg = make_config("Summary_Async_ChaCha", false, true);
        cfg.mode = WriteMode::Async;
        auto* logger = Logger::create(cfg);
        results.push_back(run_benchmark("Async | ChaCha20", logger, iterations * 3, msg_size));
        Logger::release("Summary_Async_ChaCha");
    }
    {
        auto cfg = make_config("Summary_Async_Both", true, true);
        cfg.mode = WriteMode::Async;
        auto* logger = Logger::create(cfg);
        results.push_back(run_benchmark("Async | Zstd+ChaCha20", logger, iterations * 3, msg_size));
        Logger::release("Summary_Async_Both");
    }
    
    for (const auto& r : results) {
        print_result(r);
    }
    
    std::cout << "========================================================================\n";
    std::cout << "Message size: " << msg_size << " bytes\n";
    std::cout << "========================================================================\n\n";
}

// ============================================================================
// Multi-threaded Benchmark
// ============================================================================

TEST_F(BenchmarkTest, MultiThreaded_Async) {
    auto cfg = make_config("MTAsync", false, false);
    cfg.mode = WriteMode::Async;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    constexpr int num_threads = 4;
    constexpr int iterations_per_thread = 10000;
    constexpr int msg_size = 128;
    std::string message(msg_size, 'Y');
    
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<std::thread> threads;
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([logger, &message, iterations_per_thread]() {
            for (int i = 0; i < iterations_per_thread; ++i) {
                logger->info("MT", "{}", message);
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    logger->flush_sync();
    
    auto end = std::chrono::high_resolution_clock::now();
    double total_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    int total_ops = num_threads * iterations_per_thread;
    double ops_per_second = total_ops / (total_ms / 1000.0);
    double mb_per_second = (static_cast<double>(total_ops) * msg_size / (1024.0 * 1024.0)) / (total_ms / 1000.0);
    
    std::cout << "\n";
    std::cout << "Multi-threaded Benchmark (" << num_threads << " threads):\n";
    std::cout << "  Total operations: " << total_ops << "\n";
    std::cout << "  Total time: " << std::fixed << std::setprecision(2) << total_ms << " ms\n";
    std::cout << "  Throughput: " << std::fixed << std::setprecision(0) << ops_per_second << " ops/s\n";
    std::cout << "  Bandwidth: " << std::fixed << std::setprecision(2) << mb_per_second << " MB/s\n";
    std::cout << "\n";
    
    EXPECT_GT(ops_per_second, 10000);
}

// ============================================================================
// Latency Distribution Test
// ============================================================================

TEST_F(BenchmarkTest, LatencyDistribution_Async) {
    auto cfg = make_config("LatencyTest", false, false);
    cfg.mode = WriteMode::Async;
    auto* logger = Logger::create(cfg);
    ASSERT_NE(logger, nullptr);
    
    constexpr int iterations = 10000;
    constexpr int msg_size = 128;
    std::string message(msg_size, 'Z');
    
    std::vector<double> latencies;
    latencies.reserve(iterations);
    
    // Warmup
    for (int i = 0; i < 1000; ++i) {
        logger->info("Lat", "{}", message);
    }
    logger->flush_sync();
    
    // Measure individual latencies
    for (int i = 0; i < iterations; ++i) {
        auto start = std::chrono::high_resolution_clock::now();
        logger->info("Lat", "{}", message);
        auto end = std::chrono::high_resolution_clock::now();
        latencies.push_back(std::chrono::duration<double, std::micro>(end - start).count());
    }
    logger->flush_sync();
    
    // Calculate statistics
    std::sort(latencies.begin(), latencies.end());
    double min = latencies.front();
    double max = latencies.back();
    double median = latencies[iterations / 2];
    double p99 = latencies[static_cast<size_t>(iterations * 0.99)];
    double p999 = latencies[static_cast<size_t>(iterations * 0.999)];
    double avg = std::accumulate(latencies.begin(), latencies.end(), 0.0) / iterations;
    
    std::cout << "\n";
    std::cout << "Async Mode Latency Distribution (128B messages):\n";
    std::cout << "  Min:    " << std::fixed << std::setprecision(2) << min << " us\n";
    std::cout << "  Avg:    " << avg << " us\n";
    std::cout << "  Median: " << median << " us\n";
    std::cout << "  P99:    " << p99 << " us\n";
    std::cout << "  P99.9:  " << p999 << " us\n";
    std::cout << "  Max:    " << max << " us\n";
    std::cout << "\n";
    
    // Async mode should have very low latency (< 100us average)
    EXPECT_LT(avg, 100.0);
}

// ============================================================================
// Compression Ratio Test
// ============================================================================

TEST_F(BenchmarkTest, CompressionRatio) {
    // Use larger data set for accurate compression ratio measurement
    // Zstd needs sufficient data to build dictionary and show real compression
    constexpr int iterations = 50000;  // 10x more data
    
    std::cout << "\n";
    std::cout << "========================================================================\n";
    std::cout << "                    COMPRESSION RATIO ANALYSIS\n";
    std::cout << "========================================================================\n";
    
    // Test different message patterns
    struct TestCase {
        std::string name;
        std::function<std::string(int)> message_generator;
        int msg_size_approx;  // For reference
    };
    
    std::vector<TestCase> test_cases = {
        // Highly compressible: repeated characters
        {"Repeated chars (AAAA...)", [](int) { 
            return std::string(256, 'A'); 
        }, 256},
        
        // Moderately compressible: typical log messages
        {"Typical log messages", [](int i) { 
            return "INFO [2026-01-06 12:34:56.789] [MainThread] Processing request #" + 
                   std::to_string(i) + " from user session, elapsed time: 123ms, status: OK"; 
        }, 120},
        
        // JSON-like structured logs
        {"JSON structured logs", [](int i) {
            return R"({"level":"INFO","timestamp":"2026-01-06T12:34:56.789Z","thread":"main","message":"Request processed","request_id":)" + 
                   std::to_string(i) + R"(,"duration_ms":123,"status":"success","user":"test"})";
        }, 180},
        
        // High entropy: truly random printable ASCII using MT19937
        {"High entropy random", [](int i) {
            std::mt19937 gen(static_cast<uint32_t>(i));
            std::uniform_int_distribution<int> dist(33, 126);  // Printable ASCII
            std::string s;
            s.reserve(256);
            for (int j = 0; j < 256; ++j) {
                s += static_cast<char>(dist(gen));
            }
            return s;
        }, 256},
        
        // Binary-like: random bytes encoded as base64-ish
        {"Random binary (base64)", [](int i) {
            std::mt19937 gen(static_cast<uint32_t>(i * 12345));
            std::uniform_int_distribution<int> dist(0, 63);
            const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string s;
            s.reserve(256);
            for (int j = 0; j < 256; ++j) {
                s += b64[dist(gen)];
            }
            return s;
        }, 256},
        
        // Stack traces (highly repetitive structure)
        {"Stack traces", [](int i) {
            return "Exception in thread \"main\" java.lang.NullPointerException\n"
                   "    at com.example.MyClass.processData(MyClass.java:123)\n"
                   "    at com.example.MyService.handleRequest(MyService.java:456)\n"
                   "    at com.example.Controller.doGet(Controller.java:789)\n"
                   "    at org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:897)\n"
                   "    Request ID: " + std::to_string(i);
        }, 350},
        
        // Mixed: realistic log with some variable content
        {"Mixed real-world", [](int i) {
            std::mt19937 gen(static_cast<uint32_t>(i));
            std::uniform_int_distribution<int> latency(1, 9999);
            std::uniform_int_distribution<int> user_id(10000, 99999);
            std::uniform_int_distribution<int> status(0, 2);
            const char* statuses[] = {"success", "failure", "timeout"};
            return "Request from user_" + std::to_string(user_id(gen)) + 
                   " completed in " + std::to_string(latency(gen)) + "ms, " +
                   "status=" + statuses[status(gen)] + ", request_id=" + std::to_string(i);
        }, 100},
    };
    
    std::cout << std::left << std::setw(28) << "Message Pattern"
              << " | " << std::setw(12) << "Plain Size"
              << " | " << std::setw(12) << "Zstd Size"
              << " | " << std::setw(8) << "Ratio"
              << " | " << std::setw(8) << "Saved"
              << " | " << std::setw(10) << "Est. Raw"
              << "\n";
    std::cout << "--------------------------------------------------------------------------------\n";
    
    for (const auto& test_case : test_cases) {
        // Write without compression
        std::filesystem::path plain_dir = test_dir_ / "plain";
        std::filesystem::path zstd_dir = test_dir_ / "zstd";
        std::filesystem::create_directories(plain_dir);
        std::filesystem::create_directories(zstd_dir);
        
        // Calculate estimated raw message size (without log formatting overhead)
        std::uintmax_t raw_message_bytes = 0;
        
        {
            Config cfg;
            cfg.name_prefix = "plain";
            cfg.log_dir = plain_dir;
            cfg.cache_dir = plain_dir / "cache";
            cfg.min_level = Level::Verbose;
            cfg.mode = WriteMode::Sync;
            auto* logger = Logger::create(cfg);
            
            for (int i = 0; i < iterations; ++i) {
                auto msg = test_case.message_generator(i);
                raw_message_bytes += msg.size();
                logger->info("Test", "{}", msg);
            }
            logger->flush_sync();
            Logger::release("plain");
        }
        
        // Write with Zstd compression
        {
            Config cfg;
            cfg.name_prefix = "zstd";
            cfg.log_dir = zstd_dir;
            cfg.cache_dir = zstd_dir / "cache";
            cfg.min_level = Level::Verbose;
            cfg.compression = Compression::Zstd;
            cfg.mode = WriteMode::Sync;
            auto* logger = Logger::create(cfg);
            
            for (int i = 0; i < iterations; ++i) {
                logger->info("Test", "{}", test_case.message_generator(i));
            }
            logger->flush_sync();
            Logger::release("zstd");
        }
        
        // Calculate file sizes
        std::uintmax_t plain_size = 0;
        std::uintmax_t zstd_size = 0;
        
        for (const auto& entry : std::filesystem::directory_iterator(plain_dir)) {
            if (entry.is_regular_file()) {
                plain_size += entry.file_size();
            }
        }
        
        for (const auto& entry : std::filesystem::directory_iterator(zstd_dir)) {
            if (entry.is_regular_file()) {
                zstd_size += entry.file_size();
            }
        }
        
        double ratio = plain_size > 0 ? static_cast<double>(zstd_size) / plain_size : 0;
        double saved = (1.0 - ratio) * 100.0;
        
        // Format sizes for display
        auto format_size = [](std::uintmax_t bytes) -> std::string {
            if (bytes >= 1024 * 1024) {
                return std::to_string(bytes / (1024 * 1024)) + " MB";
            } else if (bytes >= 1024) {
                return std::to_string(bytes / 1024) + " KB";
            }
            return std::to_string(bytes) + " B";
        };
        
        std::cout << std::left << std::setw(28) << test_case.name
                  << " | " << std::right << std::setw(10) << format_size(plain_size)
                  << " | " << std::setw(10) << format_size(zstd_size)
                  << " | " << std::setw(6) << std::fixed << std::setprecision(2) << ratio << "x"
                  << " | " << std::setw(6) << std::setprecision(1) << saved << "%"
                  << " | " << std::setw(10) << format_size(raw_message_bytes)
                  << "\n";
        
        // Cleanup for next test
        std::filesystem::remove_all(plain_dir);
        std::filesystem::remove_all(zstd_dir);
    }
    
    std::cout << "================================================================================\n";
    std::cout << "Iterations: " << iterations << " | Est. Raw = message content only (no log format overhead)\n";
    std::cout << "================================================================================\n\n";
}

// ============================================================================
// Compression Level Comparison Test
// ============================================================================

TEST_F(BenchmarkTest, CompressionLevelComparison) {
    constexpr int iterations = 20000;
    
    std::cout << "\n";
    std::cout << "========================================================================\n";
    std::cout << "                ZSTD COMPRESSION LEVEL COMPARISON\n";
    std::cout << "========================================================================\n";
    
    // Generate typical log messages
    auto generate_message = [](int i) {
        std::mt19937 gen(static_cast<uint32_t>(i));
        std::uniform_int_distribution<int> latency(1, 9999);
        return "INFO [2026-01-06 12:34:56.789] [MainThread] Processing request #" + 
               std::to_string(i) + " from user session, elapsed time: " + 
               std::to_string(latency(gen)) + "ms, status: OK, transaction_id: TXN" + 
               std::to_string(i * 7 + 12345);
    };
    
    // Test representative compression levels: fast, balanced, max
    std::vector<std::pair<int, std::string>> levels = {
        {3, "Fast (default)"},
        {12, "Balanced"},
        {22, "Maximum"},
    };
    
    // First write plain for baseline
    std::filesystem::path plain_dir = test_dir_ / "plain";
    std::filesystem::create_directories(plain_dir);
    {
        Config cfg;
        cfg.name_prefix = "plain";
        cfg.log_dir = plain_dir;
        cfg.cache_dir = plain_dir / "cache";
        cfg.min_level = Level::Verbose;
        cfg.mode = WriteMode::Sync;
        auto* logger = Logger::create(cfg);
        
        for (int i = 0; i < iterations; ++i) {
            logger->info("Test", "{}", generate_message(i));
        }
        logger->flush_sync();
        Logger::release("plain");
    }
    
    std::uintmax_t plain_size = 0;
    for (const auto& entry : std::filesystem::directory_iterator(plain_dir)) {
        if (entry.is_regular_file()) {
            plain_size += entry.file_size();
        }
    }
    std::filesystem::remove_all(plain_dir);
    
    std::cout << std::left << std::setw(18) << "Level"
              << " | " << std::setw(12) << "File Size"
              << " | " << std::setw(10) << "Ratio"
              << " | " << std::setw(10) << "Saved"
              << " | " << std::setw(14) << "Write Speed"
              << " | " << std::setw(10) << "Time"
              << "\n";
    std::cout << "--------------------------------------------------------------------------------\n";
    
    // Print plain baseline
    std::cout << std::left << std::setw(18) << "Plain (no comp)"
              << " | " << std::right << std::setw(10) << (plain_size / 1024) << " KB"
              << " | " << std::setw(8) << "1.00x"
              << " | " << std::setw(8) << "0.0%"
              << " | " << std::setw(12) << "-"
              << " | " << std::setw(8) << "-"
              << "\n";
    std::cout << "------------------------------------------------------------------------\n";
    
    for (const auto& [level, level_name] : levels) {
        std::filesystem::path dir = test_dir_ / ("level_" + std::to_string(level));
        std::filesystem::create_directories(dir);
        
        Config cfg;
        cfg.name_prefix = "zstd_" + std::to_string(level);
        cfg.log_dir = dir;
        cfg.cache_dir = dir / "cache";
        cfg.min_level = Level::Verbose;
        cfg.compression = Compression::Zstd;
        cfg.compression_level = level;
        cfg.mode = WriteMode::Sync;
        
        auto* logger = Logger::create(cfg);
        
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            logger->info("Test", "{}", generate_message(i));
        }
        logger->flush_sync();
        auto end = std::chrono::high_resolution_clock::now();
        
        Logger::release(cfg.name_prefix);
        
        double time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        
        std::uintmax_t compressed_size = 0;
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (entry.is_regular_file()) {
                compressed_size += entry.file_size();
            }
        }
        
        double ratio = static_cast<double>(compressed_size) / plain_size;
        double saved = (1.0 - ratio) * 100.0;
        double speed = (iterations / (time_ms / 1000.0));
        
        std::string label = std::to_string(level) + " - " + level_name;
        std::cout << std::left << std::setw(18) << label
                  << " | " << std::right << std::setw(10) << (compressed_size / 1024) << " KB"
                  << " | " << std::setw(6) << std::fixed << std::setprecision(2) << ratio << "x"
                  << " | " << std::setw(6) << std::setprecision(1) << saved << "%"
                  << " | " << std::setw(10) << std::setprecision(0) << speed << " op/s"
                  << " | " << std::setw(6) << std::setprecision(0) << time_ms << " ms"
                  << "\n";
        
        std::filesystem::remove_all(dir);
    }
    
    std::cout << "========================================================================\n";
    std::cout << "Iterations: " << iterations << " | Default level: 3 (recommended for real-time)\n";
    std::cout << "========================================================================\n\n";
}

// ============================================================================
// Encryption Overhead Test
// ============================================================================

TEST_F(BenchmarkTest, EncryptionOverhead) {
    constexpr int iterations = 5000;
    constexpr int msg_size = 128;
    std::string message(msg_size, 'E');
    
    std::cout << "\n";
    std::cout << "========================================================================\n";
    std::cout << "                    ENCRYPTION SIZE OVERHEAD\n";
    std::cout << "========================================================================\n";
    
    struct TestConfig {
        std::string name;
        bool compress;
        bool encrypt;
    };
    
    std::vector<TestConfig> configs = {
        {"Plain (baseline)", false, false},
        {"Zstd only", true, false},
        {"ChaCha20 only", false, true},
        {"Zstd + ChaCha20", true, true},
    };
    
    std::vector<std::uintmax_t> sizes;
    
    for (const auto& tc : configs) {
        std::filesystem::path dir = test_dir_ / tc.name;
        std::filesystem::create_directories(dir);
        
        auto cfg = make_config(tc.name, tc.compress, tc.encrypt);
        cfg.log_dir = dir;
        cfg.cache_dir = dir / "cache";
        cfg.mode = WriteMode::Sync;
        
        auto* logger = Logger::create(cfg);
        for (int i = 0; i < iterations; ++i) {
            logger->info("Test", "{}", message);
        }
        logger->flush_sync();
        Logger::release(tc.name);
        
        std::uintmax_t total_size = 0;
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (entry.is_regular_file()) {
                total_size += entry.file_size();
            }
        }
        sizes.push_back(total_size);
        
        std::filesystem::remove_all(dir);
    }
    
    std::cout << std::left << std::setw(25) << "Configuration"
              << " | " << std::setw(12) << "File Size"
              << " | " << std::setw(12) << "vs Plain"
              << " | " << std::setw(15) << "Bytes/Message"
              << "\n";
    std::cout << "------------------------------------------------------------------------\n";
    
    std::uintmax_t baseline = sizes[0];
    for (size_t i = 0; i < configs.size(); ++i) {
        double vs_plain = baseline > 0 ? static_cast<double>(sizes[i]) / baseline : 0;
        double bytes_per_msg = static_cast<double>(sizes[i]) / iterations;
        
        std::cout << std::left << std::setw(25) << configs[i].name
                  << " | " << std::right << std::setw(10) << sizes[i] << " B"
                  << " | " << std::setw(10) << std::fixed << std::setprecision(2) << vs_plain << "x"
                  << " | " << std::setw(13) << std::setprecision(1) << bytes_per_msg << " B"
                  << "\n";
    }
    
    std::cout << "========================================================================\n";
    std::cout << "Message size: " << msg_size << " bytes, Iterations: " << iterations << "\n";
    std::cout << "========================================================================\n\n";
}

} // anonymous namespace
} // namespace logln
