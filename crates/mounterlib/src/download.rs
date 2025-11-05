//! Download split binary parts from various sources

use anyhow::Result;
use mainlib::PartHeader;
use std::collections::HashMap;

#[cfg(feature = "download-http")]
pub mod http;

#[cfg(feature = "download-dns")]
pub mod dns;

#[cfg(feature = "download-local")]
pub mod local;

/// Downloaded part with header and data
#[derive(Debug, Clone)]
pub struct DownloadedPart {
    pub header: PartHeader,
    pub data: Vec<u8>,
}

impl DownloadedPart {
    pub fn new(header: PartHeader, data: Vec<u8>) -> Self {
        Self { header, data }
    }

    pub fn part_number(&self) -> u32 {
        self.header.part_number
    }

    pub fn data_size(&self) -> usize {
        self.data.len()
    }

    pub fn validate(&self) -> Result<()> {
        self.header.validate_data(&self.data)
    }
}

// Trait for implementing custom download methods
pub trait Downloader {
    fn download_part(&self, source: &str, timeout: u64) -> Result<DownloadedPart>;

    fn download_all(&self, sources: &[&str], timeout: u64) -> Result<Vec<DownloadedPart>> {
        let mut parts = Vec::new();
        for source in sources {
            let part = self.download_part(source, timeout)?;
            parts.push(part);
        }
        Ok(parts)
    }
}

/// Convert a vector of DownloadedPart into a HashMap for reconstruction
pub fn parts_to_map(parts: Vec<DownloadedPart>) -> Result<HashMap<u32, (PartHeader, Vec<u8>)>> {
    let mut map = HashMap::new();

    for part in parts {
        let part_num = part.part_number();

        if map.contains_key(&part_num) {
            anyhow::bail!("Duplicate part number detected: {}", part_num);
        }

        map.insert(part_num, (part.header, part.data));
    }

    Ok(map)
}

/// Validate all parts before reconstruction
pub fn validate_all_parts(parts: &[DownloadedPart]) -> Result<()> {
    if parts.is_empty() {
        anyhow::bail!("No parts provided");
    }

    for part in parts {
        part.validate()
            .map_err(|e| anyhow::anyhow!("Part {} validation failed: {}", part.part_number(), e))?;
    }

    Ok(())
}
