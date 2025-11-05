//! Local filesystem loading functionality

use anyhow::{Context, Result};
use mainlib::{PartHeader, HEADER_SIZE_V1, HEADER_SIZE_V2, HEADER_VERSION_V1, HEADER_VERSION_V2};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::{DownloadedPart, Downloader};

/// Loads and validates a single part from a file
pub fn load_single(path: &Path) -> Result<(PartHeader, Vec<u8>)> {
    let full_data = load_from_file(path)?;
    validate_minimum_size(&full_data, path)?;

    let (header, header_size) = parse_header(&full_data, path)?;
    let data = extract_data(&full_data, header_size)?;

    validate_data_size(&header, &data)?;
    
    // Skip checksum validation for encrypted parts - will be validated after decryption
    if !header.is_encrypted() {
        validate_data_checksum(&header, &data)?;
    }

    Ok((header, data))
}

/// Loads multiple parts from file paths
pub fn load_all(paths: &[PathBuf]) -> Result<Vec<DownloadedPart>> {
    let mut parts = Vec::with_capacity(paths.len());

    for path in paths {
        let (header, data) = load_single(path)
            .with_context(|| format!("Failed to load from file: {}", path.display()))?;

        parts.push(DownloadedPart::new(header, data));
    }

    Ok(parts)
}

/// Loads multiple parts and returns them as a HashMap indexed by part number
pub fn load_all_as_map(
    paths: &[PathBuf],
    verbose: bool,
) -> Result<HashMap<u32, (PartHeader, Vec<u8>)>> {
    let mut parts = HashMap::new();

    for (idx, path) in paths.iter().enumerate() {
        if verbose {
            debug_println!("  [{}/{}] Loading: {}", idx + 1, paths.len(), path.display());
        }

        let (header, data) = load_single(path)
            .with_context(|| format!("Failed to load part {} from file: {}", idx, path.display()))?;

        if verbose {
            debug_println!(
                "    ✓ Part {} of {} ({} bytes)",
                header.part_number + 1,
                header.total_parts,
                data.len()
            );
        }

        if parts.contains_key(&header.part_number) {
            anyhow::bail!(
                "Duplicate part detected: part number {} loaded more than once",
                header.part_number
            );
        }

        parts.insert(header.part_number, (header, data));
    }

    Ok(parts)
}

fn load_from_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))
}

fn validate_minimum_size(data: &[u8], path: &Path) -> Result<()> {
    if data.len() < HEADER_SIZE_V1 {
        anyhow::bail!(
            "File is too small: {} bytes (minimum: {} bytes for header) in file: {}",
            data.len(),
            HEADER_SIZE_V1,
            path.display()
        );
    }
    Ok(())
}

fn parse_header(data: &[u8], path: &Path) -> Result<(PartHeader, usize)> {
    // Read first 6 bytes to determine version
    if data.len() < 6 {
        anyhow::bail!(
            "Insufficient data to read header version in file: {}",
            path.display()
        );
    }

    let version = u16::from_le_bytes([data[4], data[5]]);

    let header_size = match version {
        HEADER_VERSION_V1 => HEADER_SIZE_V1,
        HEADER_VERSION_V2 => HEADER_SIZE_V2,
        _ => anyhow::bail!(
            "Unknown header version: {} in file: {}",
            version,
            path.display()
        ),
    };

    if data.len() < header_size {
        anyhow::bail!(
            "Insufficient data for header: {} bytes (required: {} bytes for v{} header) in file: {}",
            data.len(),
            header_size,
            version,
            path.display()
        );
    }

    let header =
        PartHeader::from_bytes(&data[..header_size]).context("Failed to parse part header")?;

    Ok((header, header_size))
}

fn extract_data(full_data: &[u8], header_size: usize) -> Result<Vec<u8>> {
    Ok(full_data[header_size..].to_vec())
}

fn validate_data_size(header: &PartHeader, data: &[u8]) -> Result<()> {
    if data.len() != header.data_size as usize {
        anyhow::bail!(
            "Data size mismatch: received {} bytes, header declares {} bytes",
            data.len(),
            header.data_size
        );
    }
    Ok(())
}

fn validate_data_checksum(header: &PartHeader, data: &[u8]) -> Result<()> {
    header
        .validate_data(data)
        .context("Data checksum validation failed")
}

pub struct LocalLoader;

impl LocalLoader {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LocalLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl Downloader for LocalLoader {
    fn download_part(&self, source: &str, _timeout: u64) -> Result<DownloadedPart> {
        let path = Path::new(source);
        let (header, data) = load_single(path)?;
        Ok(DownloadedPart::new(header, data))
    }

    fn download_all(&self, sources: &[&str], _timeout: u64) -> Result<Vec<DownloadedPart>> {
        let paths: Vec<PathBuf> = sources.iter().map(|s| PathBuf::from(s)).collect();
        load_all(&paths)
    }
}

