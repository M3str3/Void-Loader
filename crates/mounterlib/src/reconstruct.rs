//! Reassemble binary parts with validation

use anyhow::Result;
use mainlib::{calculate_checksum, hex_encode, PartHeader};
use std::collections::HashMap;

/// Reconstruct original binary from downloaded parts
pub fn rebuild_from_parts(
    parts: HashMap<u32, (PartHeader, Vec<u8>)>,
    password: Option<&str>,
    validate_checksums: bool,
    verbose: bool,
) -> Result<Vec<u8>> {
    validate_has_parts(&parts)?;

    let metadata = extract_metadata(&parts)?;

    #[cfg(debug_assertions)]
    if verbose {
        print_metadata_summary(&metadata);
    }

    validate_metadata_consistency(&parts, &metadata)?;

    validate_all_parts_present(&parts, &metadata)?;

    if verbose {
        println!("  ✓ All parts present and validated");
    }

    // Decrypt parts if needed
    let decrypted_parts = decrypt_parts_if_needed(parts, password, verbose)?;

    if verbose {
        println!("  Assembling binary...");
    }

    let reconstructed = assemble_parts(&decrypted_parts, &metadata, verbose)?;

    validate_reconstructed_size(&reconstructed, &metadata)?;

    if validate_checksums {
        if verbose {
            println!("  Verifying final checksum...");
        }

        validate_final_checksum(&reconstructed, &metadata)?;

        if verbose {
            println!("  ✓ Checksum verified correctly");
        }
    }

    Ok(reconstructed)
}

/// Rebuild without checksum validation
pub fn rebuild_without_validation(
    parts: HashMap<u32, (PartHeader, Vec<u8>)>,
    password: Option<&str>,
    verbose: bool,
) -> Result<Vec<u8>> {
    rebuild_from_parts(parts, password, false, verbose)
}

/// Quick rebuild for testing (no validation, no verbose)
pub fn quick_rebuild(parts: HashMap<u32, (PartHeader, Vec<u8>)>, password: Option<&str>) -> Result<Vec<u8>> {
    rebuild_from_parts(parts, password, false, false)
}

#[derive(Debug, Clone)]
struct ReconstructionMetadata {
    pub total_parts: u32,
    pub original_size: u64,
    pub original_checksum: [u8; 32],
}

fn extract_metadata(parts: &HashMap<u32, (PartHeader, Vec<u8>)>) -> Result<ReconstructionMetadata> {
    let (header, _) = parts
        .values()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No parts available"))?;

    Ok(ReconstructionMetadata {
        total_parts: header.total_parts,
        original_size: header.original_size,
        original_checksum: header.original_checksum,
    })
}

/// Decrypt parts if they are encrypted
fn decrypt_parts_if_needed(
    parts: HashMap<u32, (PartHeader, Vec<u8>)>,
    password: Option<&str>,
    verbose: bool,
) -> Result<HashMap<u32, (PartHeader, Vec<u8>)>> {
    let mut decrypted_parts = HashMap::new();

    for (part_num, (header, data)) in parts {
        if header.is_encrypted() {
            // Part is encrypted, need password
            let pass = password.ok_or_else(|| {
                anyhow::anyhow!(
                    "Part {} is encrypted but no password provided. Use --password flag.",
                    part_num
                )
            })?;

            if verbose {
                println!("  Decrypting part {}...", part_num);
            }

            // Derive key from password and salt from header
            let key = mainlib::crypto::derive_key_pbkdf2(pass, &header.salt);

            // Decrypt the data
            let decrypted_data = mainlib::crypto::chacha20_decrypt(&data, &key, &header.nonce);

            // Validate decrypted data matches expected checksum
            let calculated_checksum = calculate_checksum(&decrypted_data);
            if calculated_checksum != header.data_checksum {
                anyhow::bail!(
                    "Part {} decryption failed: incorrect password or corrupted data.\n\
                     Expected checksum: {}\n\
                     Got:              {}",
                    part_num,
                    hex_encode(&header.data_checksum),
                    hex_encode(&calculated_checksum)
                );
            }

            // Update header to reflect decrypted state (but keep original header info)
            let mut decrypted_header = header;
            decrypted_header.data_size = decrypted_data.len() as u64;

            decrypted_parts.insert(part_num, (decrypted_header, decrypted_data));
        } else {
            // Not encrypted, pass through as-is
            decrypted_parts.insert(part_num, (header, data));
        }
    }

    Ok(decrypted_parts)
}

fn validate_has_parts(parts: &HashMap<u32, (PartHeader, Vec<u8>)>) -> Result<()> {
    if parts.is_empty() {
        anyhow::bail!("No parts provided for reconstruction");
    }
    Ok(())
}

fn validate_metadata_consistency(
    parts: &HashMap<u32, (PartHeader, Vec<u8>)>,
    metadata: &ReconstructionMetadata,
) -> Result<()> {
    for (part_num, (header, _)) in parts {
        if header.total_parts != metadata.total_parts {
            anyhow::bail!(
                "Metadata inconsistency: part {} declares {} total parts, expected {}",
                part_num,
                header.total_parts,
                metadata.total_parts
            );
        }

        if header.original_size != metadata.original_size {
            anyhow::bail!(
                "Metadata inconsistency: part {} declares original size {} bytes, expected {} bytes",
                part_num,
                header.original_size,
                metadata.original_size
            );
        }

        if header.original_checksum != metadata.original_checksum {
            anyhow::bail!(
                "Metadata inconsistency: part {} has different original checksum",
                part_num
            );
        }
    }

    Ok(())
}

fn validate_all_parts_present(
    parts: &HashMap<u32, (PartHeader, Vec<u8>)>,
    metadata: &ReconstructionMetadata,
) -> Result<()> {
    if parts.len() != metadata.total_parts as usize {
        anyhow::bail!(
            "Missing parts: expected {} parts, but only {} downloaded",
            metadata.total_parts,
            parts.len()
        );
    }

    for i in 0..metadata.total_parts {
        if !parts.contains_key(&i) {
            anyhow::bail!("Missing part number {}", i);
        }
    }

    Ok(())
}

fn validate_reconstructed_size(data: &[u8], metadata: &ReconstructionMetadata) -> Result<()> {
    if data.len() != metadata.original_size as usize {
        anyhow::bail!(
            "Reconstructed size mismatch: got {} bytes, expected {} bytes",
            data.len(),
            metadata.original_size
        );
    }
    Ok(())
}

fn validate_final_checksum(data: &[u8], metadata: &ReconstructionMetadata) -> Result<()> {
    let calculated = calculate_checksum(data);

    if calculated != metadata.original_checksum {
        anyhow::bail!(
            "Final checksum mismatch! Binary may be corrupted.\n\
             Expected: {}\n\
             Got:      {}",
            hex_encode(&metadata.original_checksum),
            hex_encode(&calculated)
        );
    }

    Ok(())
}

fn assemble_parts(
    parts: &HashMap<u32, (PartHeader, Vec<u8>)>,
    metadata: &ReconstructionMetadata,
    verbose: bool,
) -> Result<Vec<u8>> {
    let mut reconstructed = Vec::with_capacity(metadata.original_size as usize);

    for i in 0..metadata.total_parts {
        let (_header, data) = parts
            .get(&i)
            .ok_or_else(|| anyhow::anyhow!("Part {} missing during assembly", i))?;

        if verbose {
            println!("    Part {}: {} bytes", i, data.len());
        }

        reconstructed.extend_from_slice(data);
    }

    Ok(reconstructed)
}

#[cfg(debug_assertions)]
fn print_metadata_summary(metadata: &ReconstructionMetadata) {
    println!("  Total parts expected: {}", metadata.total_parts);
    println!(
        "  Original size: {} bytes ({:.2} MB)",
        metadata.original_size,
        metadata.original_size as f64 / 1_048_576.0
    );
    println!(
        "  Original checksum: {}",
        hex_encode(&metadata.original_checksum)
    );
}

/// Get reconstruction info without rebuilding
pub fn get_reconstruction_info(
    parts: &HashMap<u32, (PartHeader, Vec<u8>)>,
) -> Result<(u64, usize, bool)> {
    if parts.is_empty() {
        return Ok((0, 0, false));
    }

    let metadata = extract_metadata(parts)?;
    let all_present = parts.len() == metadata.total_parts as usize
        && (0..metadata.total_parts).all(|i| parts.contains_key(&i));

    Ok((metadata.original_size, parts.len(), all_present))
}
