// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "sink.hpp"
#include "logln/platform.hpp"

#include <format>
#include <ctime>
#include <chrono>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <cstring>
#include <mutex>

#ifdef _WIN32
#include <io.h>
#define fileno _fileno
#else
#include <unistd.h>
#endif

namespace logln {

// ============================================================================
// FileSink Implementation
// ============================================================================

struct FileSink::Impl {
    std::filesystem::path log_dir;
    std::string name_prefix;
    std::uint64_t max_file_size = 0;
    bool binary_mode = false;  // true = .blog (binary), false = .log (text)
    
    std::FILE* file = nullptr;
    std::filesystem::path current_path;
    std::time_t file_open_time = 0;
    std::mutex mutex;
    
    Impl(const std::filesystem::path& dir, const std::string& prefix, 
         std::uint64_t max_size, bool binary)
        : log_dir(dir), name_prefix(prefix), max_file_size(max_size), binary_mode(binary) {
        // Create directories if they don't exist
        std::error_code ec;
        std::filesystem::create_directories(log_dir, ec);
    }
    
    ~Impl() {
        close_file();
    }
    
    bool open_file() {
        auto tv = get_timestamp();
        int index = 0;
        
        if (max_file_size > 0) {
            auto prefix = name_prefix + "_" + format_date_compact(tv);
            index = get_next_file_index(prefix);
        }
        
        auto filename = make_filename(tv, index);
        current_path = log_dir / filename;
        
        file = std::fopen(current_path.string().c_str(), "ab");
        if (!file) return false;
        
        file_open_time = tv.tv_sec;
        return true;
    }
    
    void close_file() {
        if (file) {
            std::fclose(file);
            file = nullptr;
        }
        file_open_time = 0;
    }
    
    bool should_rotate() const {
        if (!file) return false;
        
        auto tv = get_timestamp();
        
        // Check date change
        std::time_t open_time = file_open_time;
        std::tm open_tm{}, now_tm{};
        
#ifdef _WIN32
        localtime_s(&open_tm, &open_time);
        localtime_s(&now_tm, &tv.tv_sec);
#else
        localtime_r(&open_time, &open_tm);
        localtime_r(&tv.tv_sec, &now_tm);
#endif
        
        if (open_tm.tm_year != now_tm.tm_year ||
            open_tm.tm_mon != now_tm.tm_mon ||
            open_tm.tm_mday != now_tm.tm_mday) {
            return true;
        }
        
        // Check file size
        if (max_file_size > 0) {
            long pos = std::ftell(file);
            if (pos > 0 && static_cast<std::uint64_t>(pos) >= max_file_size) {
                return true;
            }
        }
        
        return false;
    }
    
    std::string make_filename(const timeval& tv, int index = 0) const {
        // Format: prefix_YYYYMMDD_HHMMSS_mmm.log/blog
        auto datetime_str = format_datetime_compact(tv);
        const char* ext = binary_mode ? ".blog" : ".log";
        
        if (index > 0) {
            return std::format("{}_{}_{}{}", name_prefix, datetime_str, index, ext);
        } else {
            return std::format("{}_{}{}", name_prefix, datetime_str, ext);
        }
    }
    
    int get_next_file_index(const std::string& prefix) const {
        int max_index = 0;
        std::error_code ec;
        const char* ext = binary_mode ? ".blog" : ".log";
        
        for (const auto& entry : std::filesystem::directory_iterator(log_dir, ec)) {
            if (!entry.is_regular_file()) continue;
            
            auto filename = entry.path().filename().string();
            if (!filename.starts_with(prefix)) continue;
            if (!filename.ends_with(ext)) continue;
            
            // Parse index from filename
            auto stem = entry.path().stem().string();
            auto last_underscore = stem.rfind('_');
            if (last_underscore != std::string::npos && 
                last_underscore > prefix.size()) {
                try {
                    int idx = std::stoi(stem.substr(last_underscore + 1));
                    max_index = std::max(max_index, idx);
                } catch (...) {}
            }
        }
        
        // Check if current max index file is full
        auto filename = make_filename(get_timestamp(), max_index);
        auto check_path = log_dir / filename;
        
        if (std::filesystem::exists(check_path, ec)) {
            auto size = std::filesystem::file_size(check_path, ec);
            if (!ec && size >= max_file_size) {
                return max_index + 1;
            }
        }
        
        return max_index;
    }
};

FileSink::FileSink(const std::filesystem::path& log_dir,
                   const std::string& name_prefix,
                   std::uint64_t max_file_size,
                   bool binary_mode)
    : impl_(std::make_unique<Impl>(log_dir, name_prefix, max_file_size, binary_mode)) {
}

FileSink::~FileSink() = default;

void FileSink::write(std::string_view data) {
    if (data.empty()) return;
    
    std::lock_guard lock(impl_->mutex);
    
    if (impl_->should_rotate()) {
        impl_->close_file();
    }
    
    if (!impl_->file && !impl_->open_file()) {
        return;
    }
    
    std::fwrite(data.data(), 1, data.size(), impl_->file);
}

void FileSink::flush() {
    std::lock_guard lock(impl_->mutex);
    if (impl_->file) {
        std::fflush(impl_->file);
    }
}

void FileSink::set_max_size(std::uint64_t size) {
    impl_->max_file_size = size;
}

std::filesystem::path FileSink::current_path() const {
    return impl_->current_path;
}

std::vector<std::filesystem::path> FileSink::get_files_by_date(int days_ago) const {
    std::vector<std::filesystem::path> result;
    
    auto tv = get_timestamp();
    tv.tv_sec -= days_ago * 24 * 60 * 60;
    
    auto date_str = format_date_compact(tv);
    auto prefix = impl_->name_prefix + "_" + date_str;
    const char* ext = impl_->binary_mode ? ".blog" : ".log";
    
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(impl_->log_dir, ec)) {
        if (entry.is_regular_file()) {
            auto filename = entry.path().filename().string();
            if (filename.starts_with(prefix) && filename.ends_with(ext)) {
                result.push_back(entry.path());
            }
        }
    }
    
    std::sort(result.begin(), result.end());
    return result;
}

void FileSink::cleanup_expired(std::chrono::seconds max_age) {
    std::error_code ec;
    const char* ext = impl_->binary_mode ? ".blog" : ".log";
    
    for (const auto& entry : std::filesystem::directory_iterator(impl_->log_dir, ec)) {
        if (entry.is_regular_file() && entry.path().extension() == ext) {
            auto mtime = std::filesystem::last_write_time(entry.path(), ec);
            if (ec) continue;
            
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                std::filesystem::file_time_type::clock::now() - mtime
            ).count();
            
            if (age > max_age.count()) {
                std::filesystem::remove(entry.path(), ec);
            }
        }
    }
}

} // namespace logln
