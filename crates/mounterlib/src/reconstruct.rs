//! Reassemble binary parts with validation

use anyhow::Result;
use mainlib::{calculate_checksum, hex_encode, PartHeader};
use std::collections::HashMap;

/// Reconstruct original binary from downloaded parts
pub fn rebuild_from_parts(
    parts: HashMap<u32, (PartHeader, Vec<u8>)>,
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
        debug_println!("  ✓ All parts present and validated");
        debug_println!("  Assembling binary...");
    }

    let reconstructed = assemble_parts(&parts, &metadata, verbose)?;

    validate_reconstructed_size(&reconstructed, &metadata)?;

    if validate_checksums {
        if verbose {
            debug_println!("  Verifying final checksum...");
        }

        validate_final_checksum(&reconstructed, &metadata)?;

        if verbose {
            debug_println!("  ✓ Checksum verified correctly");
        }
    }

    Ok(reconstructed)
}

/// Rebuild without checksum validation
pub fn rebuild_without_validation(
    parts: HashMap<u32, (PartHeader, Vec<u8>)>,
    verbose: bool,
) -> Result<Vec<u8>> {
    rebuild_from_parts(parts, false, verbose)
}

/// Quick rebuild for testing (no validation, no verbose)
pub fn quick_rebuild(parts: HashMap<u32, (PartHeader, Vec<u8>)>) -> Result<Vec<u8>> {
    rebuild_from_parts(parts, false, false)
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
            debug_println!("    Part {}: {} bytes", i, data.len());
        }

        reconstructed.extend_from_slice(data);
    }

    Ok(reconstructed)
}

#[cfg(debug_assertions)]
fn print_metadata_summary(metadata: &ReconstructionMetadata) {
    debug_println!("  Total parts expected: {}", metadata.total_parts);
    debug_println!(
        "  Original size: {} bytes ({:.2} MB)",
        metadata.original_size,
        metadata.original_size as f64 / 1_048_576.0
    );
    debug_println!(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_header(
        part_number: u32,
        total_parts: u32,
        data_size: u64,
        original_size: u64,
    ) -> PartHeader {
        let data_checksum = [0u8; 32];
        let original_checksum = [1u8; 32];

        PartHeader::new(
            part_number,
            total_parts,
            data_size,
            original_size,
            data_checksum,
            original_checksum,
        )
    }

    #[test]
    fn test_validate_has_parts() {
        let empty: HashMap<u32, (PartHeader, Vec<u8>)> = HashMap::new();
        assert!(validate_has_parts(&empty).is_err());

        let mut non_empty = HashMap::new();
        non_empty.insert(0, (create_test_header(0, 1, 10, 10), vec![0u8; 10]));
        assert!(validate_has_parts(&non_empty).is_ok());
    }

    #[test]
    fn test_validate_all_parts_present() {
        let mut parts = HashMap::new();
        parts.insert(0, (create_test_header(0, 2, 10, 20), vec![0u8; 10]));
        parts.insert(1, (create_test_header(1, 2, 10, 20), vec![0u8; 10]));

        let metadata = ReconstructionMetadata {
            total_parts: 2,
            original_size: 20,
            original_checksum: [1u8; 32],
        };

        assert!(validate_all_parts_present(&parts, &metadata).is_ok());
    }

    #[test]
    fn test_validate_missing_part() {
        let mut parts = HashMap::new();
        parts.insert(0, (create_test_header(0, 3, 10, 30), vec![0u8; 10]));
        parts.insert(2, (create_test_header(2, 3, 10, 30), vec![0u8; 10]));

        let metadata = ReconstructionMetadata {
            total_parts: 3,
            original_size: 30,
            original_checksum: [1u8; 32],
        };

        assert!(validate_all_parts_present(&parts, &metadata).is_err());
    }

    #[test]
    fn test_reconstruct_simple() {
        let original_data = b"Hello, World! This is a test.";
        let checksum = calculate_checksum(original_data);

        // Split into 2 parts
        let part1_data = &original_data[..15];
        let part2_data = &original_data[15..];

        let mut parts = HashMap::new();

        let header1 = PartHeader::new(
            0,
            2,
            part1_data.len() as u64,
            original_data.len() as u64,
            calculate_checksum(part1_data),
            checksum,
        );

        let header2 = PartHeader::new(
            1,
            2,
            part2_data.len() as u64,
            original_data.len() as u64,
            calculate_checksum(part2_data),
            checksum,
        );

        parts.insert(0, (header1, part1_data.to_vec()));
        parts.insert(1, (header2, part2_data.to_vec()));

        let result = rebuild_from_parts(parts, true, false).unwrap();
        assert_eq!(result, original_data);
    }

    #[test]
    fn test_quick_rebuild() {
        let original_data = b"Quick test";
        let checksum = calculate_checksum(original_data);

        let mut parts = HashMap::new();
        let header = PartHeader::new(
            0,
            1,
            original_data.len() as u64,
            original_data.len() as u64,
            checksum,
            checksum,
        );

        parts.insert(0, (header, original_data.to_vec()));

        let result = quick_rebuild(parts).unwrap();
        assert_eq!(result, original_data);
    }

    #[test]
    fn test_get_reconstruction_info() {
        let mut parts = HashMap::new();
        parts.insert(0, (create_test_header(0, 2, 10, 20), vec![0u8; 10]));
        parts.insert(1, (create_test_header(1, 2, 10, 20), vec![0u8; 10]));

        let (size, count, complete) = get_reconstruction_info(&parts).unwrap();
        assert_eq!(size, 20);
        assert_eq!(count, 2);
        assert!(complete);
    }
}
