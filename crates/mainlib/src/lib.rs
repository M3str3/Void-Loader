//! Shared library for Bricker - common structures and utilities

#![allow(dead_code)]

use anyhow::Result;
use sha2::{Digest, Sha256};

// Constants
pub const MAGIC_BYTES: &[u8; 4] = b"SPLT";
pub const HEADER_VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 96;
pub const CHECKSUM_SIZE: usize = 32;

/// Header structure for each split binary part (96 bytes total)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub part_number: u32,
    pub total_parts: u32,
    pub data_size: u64,
    pub original_size: u64,
    pub data_checksum: [u8; 32],
    pub original_checksum: [u8; 32],
    _padding: [u8; 2],
}

impl PartHeader {
    pub fn new(
        part_number: u32,
        total_parts: u32,
        data_size: u64,
        original_size: u64,
        data_checksum: [u8; 32],
        original_checksum: [u8; 32],
    ) -> Self {
        Self {
            magic: *MAGIC_BYTES,
            version: HEADER_VERSION,
            part_number,
            total_parts,
            data_size,
            original_size,
            data_checksum,
            original_checksum,
            _padding: [0; 2],
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_SIZE);

        bytes.extend_from_slice(&self.magic);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.part_number.to_le_bytes());
        bytes.extend_from_slice(&self.total_parts.to_le_bytes());
        bytes.extend_from_slice(&self.data_size.to_le_bytes());
        bytes.extend_from_slice(&self.original_size.to_le_bytes());
        bytes.extend_from_slice(&self.data_checksum);
        bytes.extend_from_slice(&self.original_checksum);
        bytes.extend_from_slice(&self._padding);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            anyhow::bail!(
                "Insufficient data for header: {} bytes (required: {})",
                bytes.len(),
                HEADER_SIZE
            );
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);

        if &magic != MAGIC_BYTES {
            anyhow::bail!(
                "Invalid magic bytes: expected 'SPLT', found '{}'",
                String::from_utf8_lossy(&magic)
            );
        }

        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != HEADER_VERSION {
            anyhow::bail!(
                "Unsupported header version: {} (expected: {})",
                version,
                HEADER_VERSION
            );
        }

        let part_number = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        let total_parts = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
        let data_size = u64::from_le_bytes([
            bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21],
        ]);
        let original_size = u64::from_le_bytes([
            bytes[22], bytes[23], bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29],
        ]);

        let mut data_checksum = [0u8; 32];
        data_checksum.copy_from_slice(&bytes[30..62]);

        let mut original_checksum = [0u8; 32];
        original_checksum.copy_from_slice(&bytes[62..94]);

        Ok(Self {
            magic,
            version,
            part_number,
            total_parts,
            data_size,
            original_size,
            data_checksum,
            original_checksum,
            _padding: [0; 2],
        })
    }

    pub fn validate_data(&self, data: &[u8]) -> Result<()> {
        if data.len() != self.data_size as usize {
            anyhow::bail!(
                "Data size mismatch: {} bytes (expected: {} bytes)",
                data.len(),
                self.data_size
            );
        }

        let calculated_checksum = calculate_checksum(data);
        if calculated_checksum != self.data_checksum {
            anyhow::bail!(
                "Data checksum mismatch. Data may be corrupted.\n\
                 Expected: {}\n\
                 Got:      {}",
                hex_encode(&self.data_checksum),
                hex_encode(&calculated_checksum)
            );
        }

        Ok(())
    }
}

pub fn calculate_checksum(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&result);
    checksum
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_serialization() {
        let original = PartHeader::new(0, 3, 1024, 3072, [1u8; 32], [2u8; 32]);
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);
        let parsed = PartHeader::from_bytes(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_invalid_magic_bytes() {
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[0..4].copy_from_slice(b"XXXX");
        let result = PartHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_checksum_validation() {
        let data = b"Hello, World!";
        let checksum = calculate_checksum(data);
        let header = PartHeader::new(
            0,
            1,
            data.len() as u64,
            data.len() as u64,
            checksum,
            checksum,
        );
        assert!(header.validate_data(data).is_ok());
    }

    #[test]
    fn test_checksum_mismatch() {
        let data = b"Hello, World!";
        let wrong_checksum = [0u8; 32];
        let header = PartHeader::new(
            0,
            1,
            data.len() as u64,
            data.len() as u64,
            wrong_checksum,
            wrong_checksum,
        );
        assert!(header.validate_data(data).is_err());
    }

    #[test]
    fn test_hex_encode() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(hex_encode(&bytes), "deadbeef");
    }

    #[test]
    fn test_validate_part_number() {
        assert!(validate_part_number(0, 3).is_ok());
        assert!(validate_part_number(2, 3).is_ok());
        assert!(validate_part_number(3, 3).is_err());
        assert!(validate_part_number(10, 3).is_err());
    }
}
