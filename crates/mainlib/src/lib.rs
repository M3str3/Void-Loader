//! Shared library for Bricker - common structures and utilities

#![allow(dead_code)]

use anyhow::Result;
use sha2::{Digest, Sha256};

pub mod crypto;

// Constants
pub const MAGIC_BYTES: &[u8; 4] = b"SPLT";
pub const HEADER_VERSION_V1: u16 = 1;
pub const HEADER_VERSION_V2: u16 = 2;
pub const HEADER_SIZE_V1: usize = 96;
pub const HEADER_SIZE_V2: usize = 128;
pub const HEADER_SIZE: usize = HEADER_SIZE_V1; // For backward compatibility
pub const CHECKSUM_SIZE: usize = 32;

// Crypto flags
pub const FLAG_ENCRYPTED: u8 = 0x01;

/// Header structure for each split binary part
/// v1: 96 bytes, v2: 128 bytes (with crypto fields)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub flags: u8,
    pub reserved: u8,
    pub part_number: u32,
    pub total_parts: u32,
    pub data_size: u64,
    pub original_size: u64,
    pub data_checksum: [u8; 32],
    pub original_checksum: [u8; 32],
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    _padding: [u8; 4],
}

impl PartHeader {
    /// Create a new v1 header (no encryption) - for backward compatibility
    pub fn new(
        part_number: u32,
        total_parts: u32,
        data_size: u64,
        original_size: u64,
        data_checksum: [u8; 32],
        original_checksum: [u8; 32],
    ) -> Self {
        Self::new_v1(
            part_number,
            total_parts,
            data_size,
            original_size,
            data_checksum,
            original_checksum,
        )
    }

    /// Create a new v1 header (no encryption)
    pub fn new_v1(
        part_number: u32,
        total_parts: u32,
        data_size: u64,
        original_size: u64,
        data_checksum: [u8; 32],
        original_checksum: [u8; 32],
    ) -> Self {
        Self {
            magic: *MAGIC_BYTES,
            version: HEADER_VERSION_V1,
            flags: 0,
            reserved: 0,
            part_number,
            total_parts,
            data_size,
            original_size,
            data_checksum,
            original_checksum,
            salt: [0; 16],
            nonce: [0; 12],
            _padding: [0; 4],
        }
    }

    /// Create a new v2 header (with encryption)
    pub fn new_v2(
        part_number: u32,
        total_parts: u32,
        data_size: u64,
        original_size: u64,
        data_checksum: [u8; 32],
        original_checksum: [u8; 32],
        salt: [u8; 16],
        nonce: [u8; 12],
    ) -> Self {
        Self {
            magic: *MAGIC_BYTES,
            version: HEADER_VERSION_V2,
            flags: FLAG_ENCRYPTED,
            reserved: 0,
            part_number,
            total_parts,
            data_size,
            original_size,
            data_checksum,
            original_checksum,
            salt,
            nonce,
            _padding: [0; 4],
        }
    }

    /// Check if this header indicates encrypted data
    pub fn is_encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let header_size = if self.version == HEADER_VERSION_V2 {
            HEADER_SIZE_V2
        } else {
            HEADER_SIZE_V1
        };
        
        let mut bytes = Vec::with_capacity(header_size);

        bytes.extend_from_slice(&self.magic);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.push(self.flags);
        bytes.push(self.reserved);
        bytes.extend_from_slice(&self.part_number.to_le_bytes());
        bytes.extend_from_slice(&self.total_parts.to_le_bytes());
        bytes.extend_from_slice(&self.data_size.to_le_bytes());
        bytes.extend_from_slice(&self.original_size.to_le_bytes());
        bytes.extend_from_slice(&self.data_checksum);
        bytes.extend_from_slice(&self.original_checksum);
        
        if self.version == HEADER_VERSION_V2 {
            bytes.extend_from_slice(&self.salt);
            bytes.extend_from_slice(&self.nonce);
            bytes.extend_from_slice(&self._padding);
        } else {
            // v1 padding
            bytes.extend_from_slice(&[0u8; 2]);
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE_V1 {
            anyhow::bail!(
                "Insufficient data for header: {} bytes (required at least: {})",
                bytes.len(),
                HEADER_SIZE_V1
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
        
        if version != HEADER_VERSION_V1 && version != HEADER_VERSION_V2 {
            anyhow::bail!(
                "Unsupported header version: {} (expected: {} or {})",
                version,
                HEADER_VERSION_V1,
                HEADER_VERSION_V2
            );
        }

        let flags = bytes[6];
        let reserved = bytes[7];
        let part_number = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let total_parts = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let data_size = u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], 
            bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        let original_size = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], 
            bytes[28], bytes[29], bytes[30], bytes[31],
        ]);

        let mut data_checksum = [0u8; 32];
        data_checksum.copy_from_slice(&bytes[32..64]);

        let mut original_checksum = [0u8; 32];
        original_checksum.copy_from_slice(&bytes[64..96]);

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];

        if version == HEADER_VERSION_V2 {
            if bytes.len() < HEADER_SIZE_V2 {
                anyhow::bail!(
                    "Insufficient data for v2 header: {} bytes (required: {})",
                    bytes.len(),
                    HEADER_SIZE_V2
                );
            }
            salt.copy_from_slice(&bytes[96..112]);
            nonce.copy_from_slice(&bytes[112..124]);
        }

        Ok(Self {
            magic,
            version,
            flags,
            reserved,
            part_number,
            total_parts,
            data_size,
            original_size,
            data_checksum,
            original_checksum,
            salt,
            nonce,
            _padding: [0; 4],
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
