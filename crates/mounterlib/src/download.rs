//! Download split binary parts from various sources

use anyhow::Result;
use mainlib::PartHeader;
use std::collections::HashMap;

#[cfg(feature = "download-http")]
pub mod http;

#[cfg(feature = "download-dns")]
pub mod dns;

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

#[cfg(test)]
mod tests {
    use super::*;
    use mainlib::calculate_checksum;

    #[test]
    fn test_downloaded_part_creation() {
        let data = vec![0u8; 100];
        let checksum = calculate_checksum(&data);
        let header = PartHeader::new(0, 1, 100, 100, checksum, checksum);

        let part = DownloadedPart::new(header, data);
        assert_eq!(part.part_number(), 0);
        assert_eq!(part.data_size(), 100);
    }

    #[test]
    fn test_parts_to_map() {
        let data1 = vec![0u8; 50];
        let data2 = vec![1u8; 50];

        let checksum1 = calculate_checksum(&data1);
        let checksum2 = calculate_checksum(&data2);

        let header1 = PartHeader::new(0, 2, 50, 100, checksum1, [0u8; 32]);
        let header2 = PartHeader::new(1, 2, 50, 100, checksum2, [0u8; 32]);

        let parts = vec![
            DownloadedPart::new(header1, data1),
            DownloadedPart::new(header2, data2),
        ];

        let map = parts_to_map(parts).unwrap();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&0));
        assert!(map.contains_key(&1));
    }

    #[test]
    fn test_parts_to_map_duplicate() {
        let data = vec![0u8; 50];
        let checksum = calculate_checksum(&data);
        let header = PartHeader::new(0, 1, 50, 50, checksum, checksum);

        let parts = vec![
            DownloadedPart::new(header, data.clone()),
            DownloadedPart::new(header, data),
        ];

        assert!(parts_to_map(parts).is_err());
    }

    #[test]
    fn test_validate_all_parts_empty() {
        let parts: Vec<DownloadedPart> = vec![];
        assert!(validate_all_parts(&parts).is_err());
    }
}
