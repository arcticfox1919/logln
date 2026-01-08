# logln

Modern C++23 high-performance logging library, **designed for mobile development**.

## Why logln?

Mobile applications have unique logging requirements that traditional logging libraries fail to address:

| Challenge | logln Solution |
|-----------|----------------|
| **Limited storage** | Zstd compression (up to 10x reduction) |
| **Security & privacy** | ECDH + XChaCha20 encryption with forward secrecy |
| **App crashes** | Memory-mapped buffer for crash recovery |
| **Battery & performance** | Lock-free async logging, minimal CPU overhead |
| **Cross-platform** | iOS, Android, Windows, macOS, Linux |
| **FFI integration** | Pure C API for Swift, Kotlin, Flutter, React Native |

## Features

- **High-performance** async logging with lock-free queue
- **Zstd compression** - reduce log file size significantly
- **End-to-end encryption** - ECDH + XChaCha20 with forward secrecy
- **Cross-platform** - Windows, macOS, iOS, Android, Linux
- **Crash recovery** - memory-mapped buffer preserves logs on crash
- **FFI-friendly** - C API for easy bindings (Swift, Kotlin, Dart, etc.)

## Requirements

- C++23 compiler (GCC 13+, Clang 16+, MSVC 19.36+)
- CMake 3.20+

## Quick Start

For complete usage examples, see:
- **C++ API**: [examples/basic_cpp.cpp](examples/basic_cpp.cpp)
- **C API**: [examples/basic_c.c](examples/basic_c.c)
- **Unit Tests**: [tests/](tests/) - comprehensive API coverage

### C++ API (Minimal)

```cpp
#include <logln/logln.h>

auto config = logln::ConfigBuilder()
    .log_dir("./logs")
    .name("myapp")
    .build();

auto* logger = logln::Logger::create(*config);
logger->info("Main", "Hello, {}!", "World");
```

### C API (Minimal)

```c
#include <logln/logln.h>

logln_config_t config = logln_config_create();
logln_config_set_log_dir(config, "./logs");
logln_config_set_name(config, "myapp");

logln_handle_t logger = logln_create(config);
LOGLN_INFO(logger, "Main", "Hello, %s!", "World");

logln_release(logger);
logln_config_destroy(config);
```

## Log Encryption

Logln uses **ECDH key exchange + XChaCha20 stream cipher** for log encryption, providing both security and performance.

### Why Two Encryption Methods?

| Type | Speed | Key Exchange | Use Case |
|------|-------|--------------|----------|
| **Symmetric** (ChaCha20) | ⚡ Fast | ❌ Need to share key securely | Encrypt actual data |
| **Asymmetric** (ECDH) | 🐢 Slow | ✅ No pre-shared key needed | Securely derive symmetric key |

**Solution**: Use asymmetric encryption to securely establish a shared key, then use that key for fast symmetric encryption.

### Encryption Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SETUP (One-time)                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Server generates a key pair:                                              │
│   ┌──────────────────────────────────────────┐                              │
│   │  🔑 Server Private Key (SECRET!)         │  ← Keep safe, for decryption│
│   │  🔓 Server Public Key                    │  ← Embed in app config      │
│   └──────────────────────────────────────────┘                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                      APP RUNTIME (Every launch)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   1. App reads Server Public Key from config                                │
│                                                                             │
│   2. App generates TEMPORARY key pair (new every launch!):                  │
│      ┌────────────────────────────────┐                                     │
│      │  🔑 Temp Private Key           │  ← Destroyed after step 3           │
│      │  🔓 Temp Public Key            │  ← Written to log file header       │
│      └────────────────────────────────┘                                     │
│                                                                             │
│   3. ECDH key agreement:                                                    │
│                                                                             │
│      Server Public Key ─────┐                                               │
│                             ├──► ECDH ──► Shared Secret (256-bit)           │
│      Temp Private Key ──────┘             │                                 │
│                                           │                                 │
│      (Temp Private Key destroyed here) 🗑️ │                                 │
│                                           ▼                                 │
│                                    ChaCha20 Key                             │
│                                                                             │
│   4. Encrypt logs with ChaCha20:                                            │
│                                                                             │
│      "User login: alice" ──► ChaCha20(key) ──► [encrypted bytes]            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                              LOG FILE                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────────────────────┐                               │
│   │  Header                                 │                               │
│   │  ├─ Magic byte (encryption flag)        │                               │
│   │  ├─ Metadata                            │                               │
│   │  └─ 🔓 Temp Public Key (64 bytes)       │  ← Needed for decryption      │
│   ├─────────────────────────────────────────┤                               │
│   │  [Encrypted log record 1]               │                               │
│   │  [Encrypted log record 2]               │                               │
│   │  [Encrypted log record 3]               │                               │
│   │  ...                                    │                               │
│   └─────────────────────────────────────────┘                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         SERVER DECRYPTION                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   1. Read Temp Public Key from log file header                              │
│                                                                             │
│   2. ECDH key agreement (produces SAME shared secret!):                     │
│                                                                             │
│      Temp Public Key ───────┐                                               │
│                             ├──► ECDH ──► Shared Secret (256-bit)           │
│      Server Private Key ────┘             │                                 │
│                                           ▼                                 │
│                                    ChaCha20 Key                             │
│                                                                             │
│   3. Decrypt logs:                                                          │
│                                                                             │
│      [encrypted bytes] ──► ChaCha20(key) ──► "User login: alice"            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Forward Secrecy

**Key insight**: Each app launch generates a NEW temporary key pair.

```
Monday:    App starts → generates KeyPair_A → monday.blog (encrypted with Key_A)
Tuesday:   App starts → generates KeyPair_B → tuesday.blog (encrypted with Key_B)  
Wednesday: App starts → generates KeyPair_C → wednesday.blog (encrypted with Key_C)
```

**If an attacker compromises the app on Wednesday:**

| File | Can Decrypt? | Reason |
|------|--------------|--------|
| wednesday.blog | ✅ Yes | Attacker has KeyPair_C |
| tuesday.blog | ❌ No | KeyPair_B was destroyed on Tuesday |
| monday.blog | ❌ No | KeyPair_A was destroyed on Monday |

**This is Forward Secrecy**: Compromise of current keys does NOT compromise historical data.

### Usage

#### 1. Generate Server Key Pair

```bash
# Using loglnk (recommended)
loglnk
# Output:
#   PRIVATE_KEY=<64 hex chars>  ← KEEP SECRET! For decryption
#   PUBLIC_KEY=<128 hex chars>  ← Embed in app config

# Or using OpenSSL
openssl ecparam -name secp256k1 -genkey -noout -out server.pem
openssl ec -in server.pem -pubout -outform DER 2>/dev/null | tail -c 65 | xxd -p -c 65  # public key
openssl ec -in server.pem -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 32          # private key
```

#### 2. Enable Encryption in App

```cpp
logln::Config config;
config.log_dir = "./logs";
config.name_prefix = "secure_app";
config.pub_key = "04a1b2c3d4...";  // Server public key (128 hex chars)

auto logger = logln::Logger::create(config);
```

#### 3. Decrypt Logs on Server

```bash
# Using loglnd CLI tool
loglnd --private-key <server_private_key_hex> secure_app.blog
# Output: secure_app.log (plaintext)
```

### Security Properties

| Property | Description |
|----------|-------------|
| **Confidentiality** | Logs encrypted with XChaCha20-Poly1305 (256-bit) |
| **Forward Secrecy** | New ephemeral keys per session; past logs safe if current key leaks |
| **Key Security** | Private keys wiped from memory immediately after use |
| **Nonce Uniqueness** | 192-bit nonce = 128-bit random + 64-bit counter |
| **No Key Transmission** | Symmetric key derived via ECDH, never transmitted |

## Decoding Logs

Use the `loglnd` CLI tool to decode `.blog` (binary) and `.mmap` (crash recovery) files:

```bash
# Decode single file
loglnd app.blog                    # → app.log

# Decode with decryption
loglnd -k <private_key> app.blog   # → app.log

# Batch decode directory
loglnd ./logs/                     # decode all .blog/.mmap files
loglnd ./logs/ -r                  # recursive
```

## Building

```bash
# Using build script
python build.py              # Build library
python build.py test         # Build and run tests
python build.py --shared     # Build shared library

```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `LOGLN_BUILD_SHARED` | OFF | Build shared library |
| `LOGLN_BUILD_TESTS` | ON | Build unit tests |
| `LOGLN_BUILD_EXAMPLES` | OFF | Build examples |
| `LOGLN_BUILD_DECODER_LIB` | ON | Build decoder shared library |
| `LOGLN_BUILD_TOOLS` | ON | Build CLI tools (loglnd) |

## License

MIT
