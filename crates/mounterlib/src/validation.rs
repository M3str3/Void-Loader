//! Integrity and security checks

use anyhow::Result;
use mainlib::{calculate_checksum, hex_encode, PartHeader};

/// Validate part header and data
pub fn validate_part(header: &PartHeader, data: &[u8]) -> Result<()> {
    validate_data_size(header, data)?;
    validate_data_checksum(header, data)?;
    Ok(())
}

/// Validate data size matches header
pub fn validate_data_size(header: &PartHeader, data: &[u8]) -> Result<()> {
    if data.len() != header.data_size as usize {
        anyhow::bail!(
            "Data size mismatch: got {} bytes, expected {} bytes",
            data.len(),
            header.data_size
        );
    }
    Ok(())
}

/// Validate data checksum matches header
pub fn validate_data_checksum(header: &PartHeader, data: &[u8]) -> Result<()> {
    let calculated = calculate_checksum(data);

    if calculated != header.data_checksum {
        anyhow::bail!(
            "Data checksum mismatch.\n\
             Expected: {}\n\
             Got:      {}",
            hex_encode(&header.data_checksum),
            hex_encode(&calculated)
        );
    }

    Ok(())
}

/// Validate part number is within valid range
pub fn validate_part_number(part_number: u32, total_parts: u32) -> Result<()> {
    if part_number >= total_parts {
        anyhow::bail!(
            "Invalid part number: {} (total parts: {})",
            part_number,
            total_parts
        );
    }
    Ok(())
}

/// Validate total parts is reasonable
pub fn validate_total_parts(total_parts: u32) -> Result<()> {
    if total_parts == 0 {
        anyhow::bail!("Total parts cannot be zero");
    }

    if total_parts > 10000 {
        anyhow::bail!(
            "Total parts is unreasonably large: {} (max: 10000)",
            total_parts
        );
    }

    Ok(())
}

/// Validate original file size is reasonable
pub fn validate_original_size(original_size: u64) -> Result<()> {
    if original_size == 0 {
        anyhow::bail!("Original file size cannot be zero");
    }

    const MAX_SIZE: u64 = 10 * 1024 * 1024 * 1024;
    if original_size > MAX_SIZE {
        anyhow::bail!(
            "Original file size is unreasonably large: {} bytes (max: {} bytes)",
            original_size,
            MAX_SIZE
        );
    }

    Ok(())
}

/// Validate data is a valid PE binary
pub fn validate_pe_format(data: &[u8]) -> Result<()> {
    if data.len() < 64 {
        anyhow::bail!("Data too small to be a valid PE file: {} bytes", data.len());
    }

    if &data[0..2] != b"MZ" {
        anyhow::bail!("Invalid DOS signature: not a PE file");
    }

    if data.len() < 64 {
        anyhow::bail!("File too small to contain PE header offset");
    }

    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

    if pe_offset >= data.len() || pe_offset < 64 {
        anyhow::bail!("Invalid PE header offset: {}", pe_offset);
    }

    if pe_offset + 4 > data.len() {
        anyhow::bail!("File too small to contain PE signature");
    }

    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        anyhow::bail!("Invalid PE signature");
    }

    Ok(())
}

/// Quick heuristic check if data looks like binary
pub fn is_likely_binary(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    if data.len() >= 2 {
        if &data[0..2] == b"MZ" {
            return true;
        }
        if data.len() >= 4 && &data[0..4] == b"\x7fELF" {
            return true;
        }
    }

    let non_printable_count = data
        .iter()
        .take(512)
        .filter(|&&b| b < 32 && b != b'\n' && b != b'\r' && b != b'\t')
        .count();

    let sample_size = data.len().min(512);
    let non_printable_ratio = non_printable_count as f32 / sample_size as f32;

    non_printable_ratio > 0.1
}

/// Validate final checksum of reconstructed binary
pub fn validate_final_checksum(data: &[u8], expected_checksum: &[u8; 32]) -> Result<()> {
    let calculated = calculate_checksum(data);

    if &calculated != expected_checksum {
        anyhow::bail!(
            "Final checksum mismatch!\n\
             Expected: {}\n\
             Got:      {}",
            hex_encode(expected_checksum),
            hex_encode(&calculated)
        );
    }

    Ok(())
}
