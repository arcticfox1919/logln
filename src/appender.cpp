// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors
//
// Appender - Internal implementation for log file management
//
// Design: True async logging for mobile apps
// - In async mode, Appender::write() only enqueues data (lock-free, non-blocking)
// - All I/O operations happen in background thread
// - Uses moodycamel::ConcurrentQueue for high-performance lock-free queue

#include "appender.hpp"
#include "async_worker.hpp"
#include "compressor.hpp"
#include "encryptor.hpp"
#include "buffer.hpp"
#include "log_buffer.hpp"
#include "sink.hpp"
#include "logln/platform.hpp"
#include "utils.hpp"

#include <format>
#include <mutex>
#include <atomic>
#include <thread>
#include <cstring>
#include <algorithm>

namespace logln {
namespace detail {

namespace {

constexpr std::size_t kBufferBlockLength = 150 * 1024;  // 150KB
constexpr std::size_t kFlushThreshold = kBufferBlockLength / 3;
constexpr std::chrono::seconds kMinLogAliveTime{24 * 60 * 60};

} // anonymous namespace

// ============================================================================
// Appender::Impl
// ============================================================================

struct Appender::Impl {
    Config config;
    
    // Buffer layer
    std::unique_ptr<MmapBuffer> mmap_buffer;
    std::unique_ptr<LogBuffer> log_buffer;
    std::vector<std::byte> heap_storage;
    AutoBuffer flush_buffer;
    
    // Compression and encryption (always available, used based on config)
    std::unique_ptr<ICompressor> compressor;
    std::unique_ptr<IEncryptor> encryptor;
    
    // Sinks
    std::unique_ptr<FileSink> file_sink;
    std::unique_ptr<ConsoleSink> console_sink;
    
    // Async worker (lock-free queue + 2 background threads)
    AsyncWorker async_worker;
    
    // Synchronization (only for sync mode and file operations)
    std::mutex buffer_mutex;
    std::mutex file_mutex;
    
    // State
    std::atomic<WriteMode> mode{WriteMode::Async};
    std::atomic<bool> console_output{false};
    std::atomic<bool> closed{false};
    
    std::uint64_t max_file_size{0};
    std::chrono::seconds max_alive_duration{24 * 60 * 60 * 10};
    bool use_compression{false};
    bool use_encryption{false};
    
    // Recursion protection (for sync mode only)
    static thread_local std::uint32_t recursion_count;
    
    explicit Impl(const Config& cfg) : config(cfg) {
        mode.store(cfg.mode);
        console_output.store(cfg.console_output);
        max_file_size = cfg.max_file_size;
        max_alive_duration = cfg.max_alive_duration;
        use_compression = (cfg.compression != Compression::None);
        use_encryption = cfg.pub_key.has_value() && !cfg.pub_key->empty();
    }
    
    // Check if binary log format is needed (compression or encryption enabled)
    bool needs_binary_mode() const {
        return use_compression || use_encryption;
    }
    
    // ========== Buffer Helpers ==========
    
    bool buffer_write(const void* data, std::size_t len) {
        return log_buffer && log_buffer->write(data, len);
    }
    
    std::size_t buffer_length() const {
        return log_buffer ? log_buffer->length() : 0;
    }
    
    bool buffer_empty() const {
        return !log_buffer || log_buffer->empty();
    }
    
    void buffer_flush(AutoBuffer& out) {
        if (log_buffer) log_buffer->flush(out);
    }
    
    // ========== Lifecycle ==========
    
    void open() {
        // Create directories
        std::error_code ec;
        std::filesystem::create_directories(config.log_dir, ec);
        if (!config.cache_dir.empty()) {
            std::filesystem::create_directories(config.cache_dir, ec);
        }
        
        // Determine if binary mode is needed
        bool binary_mode = needs_binary_mode();
        
        // Create sinks
        file_sink = std::make_unique<FileSink>(
            config.log_dir, config.name_prefix, max_file_size, binary_mode);
        console_sink = std::make_unique<ConsoleSink>();
        
        // Setup compressor/encryptor
        ICompressor* comp_ptr = nullptr;
        IEncryptor* enc_ptr = nullptr;
        
        if (use_compression) {
            compressor = make_compressor(config.compression_level);
            comp_ptr = compressor.get();
        }

        if (use_encryption && config.pub_key.has_value()) {
            encryptor = make_encryptor(*config.pub_key);
            enc_ptr = encryptor.get();
        }
        
        // Create LogBuffer (mmap with heap fallback)
        // plain_text_mode = !binary_mode (use plain text when no compression/encryption)
        auto mmap_path = (config.cache_dir.empty() ? config.log_dir : config.cache_dir) 
                         / (config.name_prefix + ".mmap");
        
        if (auto result = MmapBuffer::create(mmap_path); result) {
            mmap_buffer = std::move(*result);
            log_buffer = std::make_unique<LogBuffer>(
                mmap_buffer->data(), mmap_buffer->capacity(), 
                comp_ptr, enc_ptr, !binary_mode);
            
            // Crash recovery (only for binary mode)
            if (binary_mode) {
                AutoBuffer recovered;
                if (log_buffer->recover(recovered) && !recovered.empty()) {
                    log_to_file(recovered.ptr(), recovered.length());
                }
            }
            log_buffer->reset();
        } else {
            heap_storage.resize(kBufferBlockLength);
            log_buffer = std::make_unique<LogBuffer>(
                heap_storage.data(), heap_storage.size(), 
                comp_ptr, enc_ptr, !binary_mode);
        }
        
        closed.store(false);
        
        // Start async worker (2 threads: log thread + flush thread)
        if (config.mode == WriteMode::Async) {
            async_worker.set_flush_interval(config.flush_interval);
            async_worker.start(
                [this](LogEntry& entry) { write_to_buffer(entry); },
                [this]() { flush_to_file(); }
            );
        }
        
        // Startup marker (only for plain text mode)
        if (!needs_binary_mode()) {
            write_startup_marker();
        }
    }
    
    void close() {
        if (closed.exchange(true)) return;
        
        async_worker.stop();
        
        // Final flush
        do_flush();
        
        // Shutdown marker (only for plain text mode)
        // Must be written AFTER all logs are flushed
        if (!needs_binary_mode()) {
            write_shutdown_marker();
        }
    }
    
    // ========== Log Thread Callback (writes to mmap buffer) ==========
    
    void write_to_buffer(LogEntry& entry) {
        // Console output
        if (console_output.load(std::memory_order_relaxed)) {
            console_sink->write(entry.formatted);
        }
        
        // Write to mmap buffer (memory operation, very fast)
        if (!log_buffer) return;
        
        // Note: No lock needed here - single consumer (log thread only)
        if (!log_buffer->write(entry.formatted.data(), entry.formatted.size())) {
            // Buffer full - this shouldn't happen often with proper sizing
            // The flush thread will clear it
        }
    }
    
    // ========== Flush Thread Callback (flushes to file) ==========
    
    void flush_to_file() {
        if (buffer_empty()) return;
        
        // Lock buffer briefly to swap out data
        flush_buffer.reset();
        buffer_flush(flush_buffer);
        
        // Write to file (may block on I/O - that's OK, we're in flush thread)
        if (!flush_buffer.empty()) {
            log_to_file(flush_buffer.ptr(), flush_buffer.length());
        }
    }
    
    // ========== Write Operations ==========
    
    void write(const Record& record, std::string&& formatted) {
        if (closed.load(std::memory_order_relaxed)) return;
        
        if (mode.load(std::memory_order_relaxed) == WriteMode::Sync) {
            write_sync(record, formatted);
        } else {
            write_async(record, std::move(formatted));
        }
    }
    
    // Sync mode: direct write (blocks caller)
    void write_sync(const Record& record, const std::string& formatted) {
        // Recursion protection
        if (++recursion_count > 1) {
            --recursion_count;
            return;
        }
        
        // Console output
        if (console_output.load(std::memory_order_relaxed)) {
            console_sink->write(formatted);
        }
        
        // Write to buffer/file
        if (!log_buffer) {
            --recursion_count;
            return;
        }
        
        std::lock_guard lock(buffer_mutex);
        AutoBuffer out;
        if (log_buffer->write_sync(formatted.data(), formatted.size(), out)) {
            log_to_file(out.ptr(), out.length());
        }
        
        --recursion_count;
    }
    
    // Async mode: enqueue and return immediately (lock-free, non-blocking)
    void write_async(const Record& record, std::string&& formatted) {
        // Lock-free enqueue via AsyncWorker (zero-copy move)
        (void)async_worker.enqueue(record.level, std::move(formatted));
    }
    
    // ========== Flush Operations ==========
    
    // Called from sync mode (needs lock)
    void do_flush() {
        std::lock_guard lock(buffer_mutex);
        flush_to_file();
    }
    
    void log_to_file(const void* data, std::size_t len) {
        if (!data || len == 0) return;
        
        std::lock_guard lock(file_mutex);
        file_sink->write({static_cast<const char*>(data), len});
        file_sink->flush();
    }
    
    // ========== Markers ==========
    
    void write_marker(const char* text) {
        if (text) log_to_file(text, std::strlen(text));
    }
    
    void write_startup_marker() {
        auto tv = get_timestamp();
        // Use ISO 8601 format: YYYY-MM-DD HH:MM:SS.uuuuuu
        auto marker = std::format("^^^^^^^^^^ {} ^^^^^^^^^^[{}]\n",
            format_timestamp_micros(tv), get_pid());
        write_marker(marker.c_str());
    }
    
    void write_shutdown_marker() {
        auto tv = get_timestamp();
        // Use ISO 8601 format: YYYY-MM-DD HH:MM:SS.uuuuuu
        auto marker = std::format("$$$$$$$$$$ {} $$$$$$$$$$[{}]\n",
            format_timestamp_micros(tv), get_pid());
        write_marker(marker.c_str());
    }
    
    // ========== File Management ==========
    
    std::vector<std::filesystem::path> get_log_files(bool include_current) const {
        std::vector<std::filesystem::path> result;
        std::error_code ec;
        
        if (config.log_dir.empty()) return result;
        
        auto current = file_sink ? file_sink->current_path() : std::filesystem::path{};
        const char* ext = needs_binary_mode() ? ".blog" : ".log";
        
        for (const auto& entry : std::filesystem::directory_iterator(config.log_dir, ec)) {
            if (!entry.is_regular_file() || entry.path().extension() != ext) continue;
            if (!entry.path().filename().string().starts_with(config.name_prefix)) continue;
            if (!include_current && !current.empty() && 
                std::filesystem::equivalent(entry.path(), current, ec)) continue;
            
            result.push_back(entry.path());
        }
        
        std::ranges::sort(result, [](const auto& a, const auto& b) {
            std::error_code ec;
            return std::filesystem::last_write_time(a, ec) < 
                   std::filesystem::last_write_time(b, ec);
        });
        
        return result;
    }
    
    std::size_t remove_expired_files(int days_ago) {
        auto files = get_log_files(false);
        std::size_t removed = 0;
        std::error_code ec;
        
        auto now = std::filesystem::file_time_type::clock::now();
        auto threshold = std::chrono::hours{24 * days_ago};
        
        for (const auto& file : files) {
            auto mtime = std::filesystem::last_write_time(file, ec);
            if (!ec && (now - mtime) > threshold) {
                if (std::filesystem::remove(file, ec)) ++removed;
            }
        }
        return removed;
    }
};

thread_local std::uint32_t Appender::Impl::recursion_count = 0;

// ============================================================================
// Appender Public API
// ============================================================================

std::unique_ptr<Appender> Appender::create(const Config& config) {
    auto appender = std::unique_ptr<Appender>(new Appender(config));
    appender->impl_->open();
    return appender;
}

Appender::Appender(const Config& config)
    : impl_(std::make_unique<Impl>(config)) {}

Appender::~Appender() { close(); }

void Appender::write(const Record& record, std::string&& formatted) {
    impl_->write(record, std::move(formatted));
}

void Appender::flush() {
    if (!impl_->closed.load()) {
        impl_->async_worker.notify();
    }
}

void Appender::flush_sync() {
    if (!impl_->closed.load()) {
        impl_->async_worker.wait_flush();
    }
}

void Appender::close() { impl_->close(); }

void Appender::set_mode(WriteMode mode) {
    auto old = impl_->mode.exchange(mode);
    if (old != mode) {
        if (mode == WriteMode::Async) {
            impl_->async_worker.set_flush_interval(impl_->config.flush_interval);
            impl_->async_worker.start(
                [this](LogEntry& entry) { impl_->write_to_buffer(entry); },
                [this]() { impl_->flush_to_file(); }
            );
        } else {
            impl_->async_worker.stop();
            impl_->do_flush();
        }
    }
}

WriteMode Appender::mode() const noexcept { return impl_->mode.load(); }

void Appender::set_console_output(bool enable) { impl_->console_output.store(enable); }
bool Appender::console_output() const noexcept { return impl_->console_output.load(); }

void Appender::set_max_file_size(std::uint64_t max_bytes) {
    impl_->max_file_size = max_bytes;
    if (impl_->file_sink) impl_->file_sink->set_max_size(max_bytes);
}

void Appender::set_max_alive_duration(std::chrono::seconds duration) {
    if (duration >= kMinLogAliveTime) impl_->max_alive_duration = duration;
}

bool Appender::get_current_log_path(std::string& out) const {
    if (impl_->config.log_dir.empty()) return false;
    out = impl_->config.log_dir.string();
    return true;
}

bool Appender::get_current_cache_path(std::string& out) const {
    if (impl_->config.cache_dir.empty()) return false;
    out = impl_->config.cache_dir.string();
    return true;
}

std::vector<std::filesystem::path> 
Appender::get_log_files_from_timespan(int days_ago, std::string_view) const {
    if (!impl_->file_sink) return {};
    return impl_->file_sink->get_files_by_date(days_ago);
}

std::vector<std::filesystem::path> Appender::get_all_log_files(bool include_current) const {
    return impl_->get_log_files(include_current);
}

std::size_t Appender::remove_log_files(const std::vector<std::filesystem::path>& files) {
    std::size_t removed = 0;
    std::error_code ec;
    auto current = impl_->file_sink ? impl_->file_sink->current_path() : std::filesystem::path{};
    
    for (const auto& file : files) {
        if (!current.empty() && std::filesystem::equivalent(file, current, ec)) continue;
        if (std::filesystem::remove(file, ec)) ++removed;
    }
    return removed;
}

void Appender::remove_log_files_async(const std::vector<std::filesystem::path>& files,
                                      RemoveCallback callback) {
    std::thread([this, files, cb = std::move(callback)]() {
        auto removed = remove_log_files(files);
        if (cb) cb(removed);
    }).detach();
}

std::size_t Appender::remove_expired_log_files(int days_ago) {
    return impl_->remove_expired_files(days_ago);
}

void Appender::remove_expired_log_files_async(int days_ago, RemoveCallback callback) {
    std::thread([this, days_ago, cb = std::move(callback)]() {
        auto removed = remove_expired_log_files(days_ago);
        if (cb) cb(removed);
    }).detach();
}

} // namespace detail
} // namespace logln
