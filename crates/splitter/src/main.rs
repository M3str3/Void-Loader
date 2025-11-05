//! Split executables into multiple parts with integrity verification

use anyhow::{Context, Result};
use clap::Parser;
use mainlib::{calculate_checksum, PartHeader};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "splitter",
    author = "M3str3 <namestre3@protonmail.com>",
    version = "0.1.0",
    about = "Split executables into multiple parts with integrity verification"
)]
struct Args {
    #[arg(value_name = "EXECUTABLE", help = "Executable file to split")]
    executable: PathBuf,

    #[arg(
        short = 'p',
        long = "pieces",
        default_value = "3",
        help = "Number of parts to create",
        value_parser = validate_pieces
    )]
    pieces: u32,

    #[arg(
        short = 'o',
        long = "output",
        help = "Output directory for split parts"
    )]
    output_dir: Option<PathBuf>,

    #[arg(short = 'n', long = "name", help = "Custom prefix for output files")]
    output_name: Option<String>,

    #[arg(
        short = 'v',
        long = "verbose",
        help = "Show detailed progress information"
    )]
    verbose: bool,

    #[arg(
        long = "password",
        help = "Encrypt fragments with ChaCha20 (requires password)"
    )]
    password: Option<String>,
}

fn validate_pieces(s: &str) -> Result<u32, String> {
    let pieces: u32 = s
        .parse()
        .map_err(|_| format!("'{}' is not a valid number", s))?;

    if pieces < 2 {
        return Err("Number of pieces must be at least 2".to_string());
    }

    Ok(pieces)
}

fn main() {
    let args = Args::parse();

    if let Err(e) = run(args) {
        eprintln!("Error: {}", e);
        let mut source = e.source();
        while let Some(cause) = source {
            eprintln!("  Caused by: {}", cause);
            source = cause.source();
        }
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<()> {
    validate_input_file(&args.executable)?;

    if args.verbose {
        println!("Reading file: {}", args.executable.display());
    }

    let original_data = read_file(&args.executable)?;
    let original_size = original_data.len() as u64;

    if args.verbose {
        println!(
            "  File size: {} bytes ({:.2} MB)",
            original_size,
            original_size as f64 / 1_048_576.0
        );
    }

    if args.verbose {
        println!("Calculating checksum...");
    }

    let original_checksum = calculate_checksum(&original_data);

    if args.verbose {
        println!("  SHA256: {}", mainlib::hex_encode(&original_checksum));
    }

    let output_config = OutputConfig::from_args(&args)?;

    if args.verbose {
        println!("Output directory: {}", output_config.directory.display());
        println!("Output prefix: {}", output_config.name_prefix);
    }

    fs::create_dir_all(&output_config.directory).context("Failed to create output directory")?;

    split_and_write_parts(
        &original_data,
        original_size,
        &original_checksum,
        args.pieces,
        &output_config,
        args.password.as_deref(),
        args.verbose,
    )?;

    println!("File split successfully into {} parts", args.pieces);
    println!("  Output directory: {}", output_config.directory.display());
    println!("  File pattern: {}.partXXX", output_config.name_prefix);

    if args.verbose {
        println!("Use mounter to download and execute these parts in memory");
    }

    Ok(())
}

struct OutputConfig {
    directory: PathBuf,
    name_prefix: String,
}

impl OutputConfig {
    fn from_args(args: &Args) -> Result<Self> {
        let directory = args
            .output_dir
            .clone()
            .or_else(|| args.executable.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));

        let name_prefix = args
            .output_name
            .clone()
            .or_else(|| {
                args.executable
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "output".to_string());

        Ok(Self {
            directory,
            name_prefix,
        })
    }
}

fn split_and_write_parts(
    data: &[u8],
    total_size: u64,
    original_checksum: &[u8; 32],
    num_parts: u32,
    config: &OutputConfig,
    password: Option<&str>,
    verbose: bool,
) -> Result<()> {
    let chunk_size = ((total_size as f64) / (num_parts as f64)).ceil() as usize;

    if verbose {
        println!("Splitting into {} parts of ~{} bytes each", num_parts, chunk_size);
    }

    for part_num in 0..num_parts {
        let start = (part_num as usize * chunk_size).min(data.len());
        let end = ((part_num + 1) as usize * chunk_size).min(data.len());
        let chunk = &data[start..end];

        if chunk.is_empty() {
            if verbose {
                println!("Skipping empty part {}", part_num);
            }
            break;
        }

        write_part(
            part_num,
            num_parts,
            chunk,
            total_size,
            original_checksum,
            config,
            password,
            verbose,
        )?;
    }

    Ok(())
}

fn write_part(
    part_number: u32,
    total_parts: u32,
    data: &[u8],
    original_size: u64,
    original_checksum: &[u8; 32],
    config: &OutputConfig,
    password: Option<&str>,
    verbose: bool,
) -> Result<()> {
    // Calculate checksum of original (unencrypted) data
    let data_checksum = calculate_checksum(data);

    let (final_data, header) = if let Some(pass) = password {
        // Generate random salt and nonce
        let salt = mainlib::crypto::generate_salt();
        let nonce = mainlib::crypto::generate_nonce();

        // Derive encryption key from password
        let key = mainlib::crypto::derive_key_pbkdf2(pass, &salt);

        // Encrypt the data
        let encrypted_data = mainlib::crypto::chacha20_encrypt(data, &key, &nonce);

        // Create v2 header with encryption metadata
        let header = mainlib::PartHeader::new_v2(
            part_number,
            total_parts,
            encrypted_data.len() as u64,
            original_size,
            data_checksum,
            *original_checksum,
            salt,
            nonce,
        );

        (encrypted_data, header)
    } else {
        // No encryption - create v1 header
        let header = mainlib::PartHeader::new_v1(
            part_number,
            total_parts,
            data.len() as u64,
            original_size,
            data_checksum,
            *original_checksum,
        );

        (data.to_vec(), header)
    };

    let output_path = config
        .directory
        .join(format!("{}.part{:03}", config.name_prefix, part_number));

    let header_size = if header.version == mainlib::HEADER_VERSION_V2 {
        mainlib::HEADER_SIZE_V2
    } else {
        mainlib::HEADER_SIZE_V1
    };

    if verbose {
        let encryption_info = if password.is_some() {
            " [ENCRYPTED]"
        } else {
            ""
        };
        println!(
            "  [{}/{}] Writing: {} ({} bytes + {} byte header){}",
            part_number + 1,
            total_parts,
            output_path.display(),
            final_data.len(),
            header_size,
            encryption_info
        );
    }

    write_part_file(&output_path, &header, &final_data)?;

    Ok(())
}

fn write_part_file(path: &Path, header: &PartHeader, data: &[u8]) -> Result<()> {
    let file =
        File::create(path).with_context(|| format!("Failed to create file: {}", path.display()))?;

    let mut writer = BufWriter::new(file);

    writer
        .write_all(&header.to_bytes())
        .context("Failed to write header")?;

    writer.write_all(data).context("Failed to write data")?;

    writer.flush().context("Failed to flush file buffer")?;

    Ok(())
}

fn validate_input_file(path: &Path) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", path.display());
    }

    if !path.is_file() {
        anyhow::bail!("Path is not a file: {}", path.display());
    }

    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))
}
