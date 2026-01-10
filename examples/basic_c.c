// SPDX-License-Identifier: MIT
// Logln C99 Basic Example
//

#include <logln/logln.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    logln_result_t result;

    // Method 1: Create with config builder API
    logln_config_t config = logln_config_create();
    if (!config) {
        fprintf(stderr, "Failed to create config\n");
        return 1;
    }

    logln_config_set_log_dir(config, "./logs");
    logln_config_set_name(config, "example_c");
    logln_config_set_min_level(config, LOGLN_LEVEL_DEBUG);
    logln_config_set_console_output(config, true);

    // Validate configuration
    result = logln_config_validate(config);
    if (result != LOGLN_OK) {
        fprintf(stderr, "Config error: %s\n", logln_result_message(result));
        logln_config_destroy(config);
        return 1;
    }

    // Create logger
    logln_handle_t logger = logln_create(config);
    logln_config_destroy(config);  // Config can be destroyed after create

    if (!logger) {
        fprintf(stderr, "Failed to create logger\n");
        return 1;
    }

    // Log messages using macros (includes file/line/function info)
    LOGLN_DEBUG(logger, "Main", "Application started");
    LOGLN_INFO(logger, "Main", "Processing %d items", 42);
    LOGLN_WARN(logger, "Network", "Connection timeout after %d seconds", 30);
    LOGLN_ERROR(logger, "Database", "Query failed: %s", "table not found");

    // Log with custom tag
    LOGLN_INFO(logger, "Config", "Loaded %d settings from %s", 5, "config.json");

    // Flush and cleanup
    logln_flush_sync(logger);
    logln_release(logger);

    printf("Logs written to ./logs/\n");
    return 0;
}

// Alternative: Create logger with options struct (single FFI call)
int example_with_options(void) {
    // Initialize options with defaults
    logln_config_options_t opts = LOGLN_CONFIG_OPTIONS_INIT;
    opts.log_dir = "./logs";
    opts.name = "example_opts";
    opts.min_level = LOGLN_LEVEL_INFO;
    opts.console_output = true;

    // Create logger in one call
    logln_handle_t logger = logln_create_with_options(&opts);
    if (!logger) {
        fprintf(stderr, "Failed to create logger\n");
        return 1;
    }

    LOGLN_INFO(logger, "App", "Hello from options API!");

    logln_release(logger);
    return 0;
}
