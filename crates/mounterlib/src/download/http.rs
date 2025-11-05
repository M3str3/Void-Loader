//! HTTP/HTTPS download functionality

use anyhow::{Context, Result};
use mainlib::{PartHeader, HEADER_SIZE_V1, HEADER_SIZE_V2, HEADER_VERSION_V1, HEADER_VERSION_V2};
use reqwest::blocking::Client;
use std::collections::HashMap;
use std::time::Duration;

use super::{DownloadedPart, Downloader};

/// Downloads and validates a single part from a URL
pub fn download_single(
    url: &str,
    timeout_secs: u64,
    user_agent: &str,
) -> Result<(PartHeader, Vec<u8>)> {
    let full_data = download_from_url(url, timeout_secs, user_agent)?;
    validate_minimum_size(&full_data)?;

    let (header, header_size) = parse_header(&full_data)?;
    let data = extract_data(&full_data, header_size)?; 

    validate_data_size(&header, &data)?;
    
    // Skip checksum validation for encrypted parts - will be validated after decryption
    if !header.is_encrypted() {
        validate_data_checksum(&header, &data)?;
    }

    Ok((header, data))
}

/// Downloads multiple parts from URLs
pub fn download_all(
    urls: &[&str],
    timeout_secs: u64,
    user_agent: &str,
) -> Result<Vec<DownloadedPart>> {
    let mut parts = Vec::with_capacity(urls.len());

    for url in urls {
        let (header, data) = download_single(url, timeout_secs, user_agent)
            .with_context(|| format!("Failed to download from URL: {}", url))?;

        parts.push(DownloadedPart::new(header, data));
    }

    Ok(parts)
}

/// Downloads multiple parts and returns them as a HashMap indexed by part number
pub fn download_all_as_map(
    urls: &[String],
    timeout_secs: u64,
    user_agent: &str,
    verbose: bool,
) -> Result<HashMap<u32, (PartHeader, Vec<u8>)>> {
    let mut parts = HashMap::new();

    for (idx, url) in urls.iter().enumerate() {
        if verbose {
            debug_println!("  [{}/{}] Downloading: {}", idx + 1, urls.len(), url);
        }

        let (header, data) = download_single(url, timeout_secs, user_agent)
            .with_context(|| format!("Failed to download part {} from URL: {}", idx, url))?;

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
                "Duplicate part detected: part number {} downloaded more than once",
                header.part_number
            );
        }

        parts.insert(header.part_number, (header, data));
    }

    Ok(parts)
}

fn download_from_url(url: &str, timeout_secs: u64, user_agent: &str) -> Result<Vec<u8>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent(user_agent)
        .build()
        .context("Failed to create HTTP client")?;

    let response = client
        .get(url)
        .send()
        .with_context(|| format!("Failed to send HTTP request to: {}", url))?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!(
            "HTTP request failed: {} {} (URL: {})",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown"),
            url
        );
    }

    let data = response
        .bytes()
        .context("Failed to read response body")?
        .to_vec();

    Ok(data)
}

fn validate_minimum_size(data: &[u8]) -> Result<()> {
    if data.len() < HEADER_SIZE_V1 {
        anyhow::bail!(
            "Downloaded file is too small: {} bytes (minimum: {} bytes for header)",
            data.len(),
            HEADER_SIZE_V1
        );
    }
    Ok(())
}

fn parse_header(data: &[u8]) -> Result<(PartHeader, usize)> {
    // Read first 6 bytes to determine version
    if data.len() < 6 {
        anyhow::bail!("Insufficient data to read header version");
    }
    
    let version = u16::from_le_bytes([data[4], data[5]]);
    
    let header_size = match version {
        HEADER_VERSION_V1 => HEADER_SIZE_V1,
        HEADER_VERSION_V2 => HEADER_SIZE_V2,
        _ => anyhow::bail!("Unknown header version: {}", version),
    };
    
    if data.len() < header_size {
        anyhow::bail!(
            "Insufficient data for header: {} bytes (required: {} bytes for v{} header)",
            data.len(),
            header_size,
            version
        );
    }
    
    let header = PartHeader::from_bytes(&data[..header_size])
        .context("Failed to parse part header")?;
    
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

pub struct HttpDownloader {
    pub user_agent: String,
}

impl HttpDownloader {
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self {
            user_agent: user_agent.into(),
        }
    }
}

impl Default for HttpDownloader {
    fn default() -> Self {
        Self {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
        }
    }
}

impl Downloader for HttpDownloader {
    fn download_part(&self, source: &str, timeout: u64) -> Result<DownloadedPart> {
        let (header, data) = download_single(source, timeout, &self.user_agent)?;
        Ok(DownloadedPart::new(header, data))
    }

    fn download_all(&self, sources: &[&str], timeout: u64) -> Result<Vec<DownloadedPart>> {
        download_all(sources, timeout, &self.user_agent)
    }
}
