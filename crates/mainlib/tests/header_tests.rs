use mainlib::*;

#[test]
fn test_header_serialization_v1() {
    let original = PartHeader::new_v1(0, 3, 1024, 3072, [1u8; 32], [2u8; 32]);
    let bytes = original.to_bytes();
    assert_eq!(bytes.len(), HEADER_SIZE_V1);
    let parsed = PartHeader::from_bytes(&bytes).unwrap();
    assert_eq!(original, parsed);
}

#[test]
fn test_header_serialization_v2() {
    let salt = [3u8; 16];
    let nonce = [4u8; 12];
    let original = PartHeader::new_v2(0, 3, 1024, 3072, [1u8; 32], [2u8; 32], salt, nonce);
    let bytes = original.to_bytes();
    assert_eq!(bytes.len(), HEADER_SIZE_V2);
    let parsed = PartHeader::from_bytes(&bytes).unwrap();
    assert_eq!(original, parsed);
    assert!(original.is_encrypted());
}

#[test]
fn test_header_backward_compatibility() {
    let original = PartHeader::new(0, 3, 1024, 3072, [1u8; 32], [2u8; 32]);
    assert_eq!(original.version, HEADER_VERSION_V1);
    assert!(!original.is_encrypted());
}

#[test]
fn test_invalid_magic_bytes() {
    let mut bytes = vec![0u8; HEADER_SIZE_V1];
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

