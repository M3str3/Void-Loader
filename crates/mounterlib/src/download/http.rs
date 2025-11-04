//! HTTP/HTTPS download functionality

use anyhow::{Context, Result};
use mainlib::{PartHeader, HEADER_SIZE};
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

    let header = parse_header(&full_data)?;
    let data = extract_data(&full_data)?;

    validate_data_size(&header, &data)?;
    validate_data_checksum(&header, &data)?;

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
    if data.len() < HEADER_SIZE {
        anyhow::bail!(
            "Downloaded file is too small: {} bytes (minimum: {} bytes for header)",
            data.len(),
            HEADER_SIZE
        );
    }
    Ok(())
}

fn parse_header(data: &[u8]) -> Result<PartHeader> {
    PartHeader::from_bytes(&data[..HEADER_SIZE]).context("Failed to parse part header")
}

fn extract_data(full_data: &[u8]) -> Result<Vec<u8>> {
    Ok(full_data[HEADER_SIZE..].to_vec())
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

#[cfg(test)]
mod tests {
    use super::*;
    use mainlib::calculate_checksum;

    #[test]
    fn test_validate_minimum_size() {
        let data = vec![0u8; HEADER_SIZE + 10];
        assert!(validate_minimum_size(&data).is_ok());

        let too_small = vec![0u8; HEADER_SIZE - 1];
        assert!(validate_minimum_size(&too_small).is_err());
    }

    #[test]
    fn test_extract_data() {
        let full_data = vec![0u8; HEADER_SIZE + 100];
        let extracted = extract_data(&full_data).unwrap();
        assert_eq!(extracted.len(), 100);
    }

    #[test]
    fn test_validate_data_size() {
        let header = PartHeader::new(0, 1, 100, 100, [0u8; 32], [0u8; 32]);
        let correct_data = vec![0u8; 100];
        assert!(validate_data_size(&header, &correct_data).is_ok());

        let wrong_data = vec![0u8; 50];
        assert!(validate_data_size(&header, &wrong_data).is_err());
    }

    #[test]
    fn test_http_downloader_creation() {
        let downloader = HttpDownloader::new("TestAgent/1.0");
        assert_eq!(downloader.user_agent, "TestAgent/1.0");

        let default_downloader = HttpDownloader::default();
        assert!(default_downloader.user_agent.contains("Mozilla"));
    }

    #[test]
    fn test_parse_header() {
        let data = vec![0u8; 100];
        let checksum = calculate_checksum(&data);
        let header = PartHeader::new(0, 1, 100, 100, checksum, checksum);
        let header_bytes = header.to_bytes();

        let parsed = parse_header(&header_bytes).unwrap();
        assert_eq!(parsed.part_number, 0);
        assert_eq!(parsed.total_parts, 1);
    }
}
