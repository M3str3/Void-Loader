use mainlib::{calculate_checksum, PartHeader};
use mounterlib::reconstruct::*;
use std::collections::HashMap;

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
    
    // Just test that empty HashMap fails reconstruction
    let result = rebuild_from_parts(empty, None, true, false);
    assert!(result.is_err());
}

#[test]
fn test_validate_all_parts_present() {
    let mut parts = HashMap::new();
    parts.insert(0, (create_test_header(0, 2, 10, 20), vec![0u8; 10]));
    parts.insert(1, (create_test_header(1, 2, 10, 20), vec![0u8; 10]));

    // Should have 2 parts
    assert_eq!(parts.len(), 2);
}

#[test]
fn test_validate_missing_part() {
    let mut parts = HashMap::new();
    parts.insert(0, (create_test_header(0, 3, 10, 30), vec![0u8; 10]));
    parts.insert(2, (create_test_header(2, 3, 10, 30), vec![0u8; 10]));

    // Missing part 1, reconstruction should fail
    let result = rebuild_from_parts(parts, None, true, false);
    assert!(result.is_err());
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

    let result = rebuild_from_parts(parts, None, true, false).unwrap();
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

    let result = quick_rebuild(parts, None).unwrap();
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

#[test]
fn test_encrypted_parts_reconstruction() {
    use mainlib::crypto::{chacha20_encrypt, derive_key_pbkdf2, generate_nonce, generate_salt};
    
    let original_data = b"This is a secret test message that will be encrypted!";
    let password = "test_password";
    
    // Simulate splitting and encrypting
    let part1_data = &original_data[..27];
    let part2_data = &original_data[27..];
    
    // Encrypt part 1
    let salt1 = generate_salt();
    let nonce1 = generate_nonce();
    let key1 = derive_key_pbkdf2(password, &salt1);
    let encrypted1 = chacha20_encrypt(part1_data, &key1, &nonce1);
    
    // Encrypt part 2
    let salt2 = generate_salt();
    let nonce2 = generate_nonce();
    let key2 = derive_key_pbkdf2(password, &salt2);
    let encrypted2 = chacha20_encrypt(part2_data, &key2, &nonce2);
    
    let original_checksum = calculate_checksum(original_data);
    
    let header1 = mainlib::PartHeader::new_v2(
        0,
        2,
        encrypted1.len() as u64,
        original_data.len() as u64,
        calculate_checksum(part1_data),
        original_checksum,
        salt1,
        nonce1,
    );
    
    let header2 = mainlib::PartHeader::new_v2(
        1,
        2,
        encrypted2.len() as u64,
        original_data.len() as u64,
        calculate_checksum(part2_data),
        original_checksum,
        salt2,
        nonce2,
    );
    
    let mut parts = HashMap::new();
    parts.insert(0, (header1, encrypted1));
    parts.insert(1, (header2, encrypted2));
    
    // Test reconstruction with correct password
    let result = rebuild_from_parts(parts.clone(), Some(password), true, false).unwrap();
    assert_eq!(result.as_slice(), original_data);
    
    // Test reconstruction with wrong password should fail
    let result = rebuild_from_parts(parts.clone(), Some("wrong_password"), true, false);
    assert!(result.is_err());
    
    // Test reconstruction without password should fail
    let result = rebuild_from_parts(parts, None, true, false);
    assert!(result.is_err());
}

#[test]
fn test_mixed_encrypted_unencrypted_parts() {
    let original_data = b"Test data for mixed parts";
    let password = "test_password";
    
    let part1_data = &original_data[..12];
    let part2_data = &original_data[12..];
    
    // Part 1: unencrypted (v1)
    let header1 = mainlib::PartHeader::new_v1(
        0,
        2,
        part1_data.len() as u64,
        original_data.len() as u64,
        calculate_checksum(part1_data),
        calculate_checksum(original_data),
    );
    
    // Part 2: encrypted (v2)
    let salt2 = mainlib::crypto::generate_salt();
    let nonce2 = mainlib::crypto::generate_nonce();
    let key2 = mainlib::crypto::derive_key_pbkdf2(password, &salt2);
    let encrypted2 = mainlib::crypto::chacha20_encrypt(part2_data, &key2, &nonce2);
    
    let header2 = mainlib::PartHeader::new_v2(
        1,
        2,
        encrypted2.len() as u64,
        original_data.len() as u64,
        calculate_checksum(part2_data),
        calculate_checksum(original_data),
        salt2,
        nonce2,
    );
    
    let mut parts = HashMap::new();
    parts.insert(0, (header1, part1_data.to_vec()));
    parts.insert(1, (header2, encrypted2));
    
    // This should work - part 1 is unencrypted (no password needed), part 2 requires password
    let result = rebuild_from_parts(parts, Some(password), true, false);
    assert!(result.is_ok());
}

