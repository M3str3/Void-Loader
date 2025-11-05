use mainlib::{calculate_checksum, PartHeader};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

// Helper function to simulate the splitter with encryption
fn split_and_encrypt(
    data: &[u8],
    num_parts: u32,
    password: Option<&str>,
    output_dir: &std::path::Path,
) -> Vec<PathBuf> {
    let original_size = data.len() as u64;
    let original_checksum = calculate_checksum(data);
    let chunk_size = ((original_size as f64) / (num_parts as f64)).ceil() as usize;

    let mut paths = Vec::new();

    for part_num in 0..num_parts {
        let start = (part_num as usize * chunk_size).min(data.len());
        let end = ((part_num + 1) as usize * chunk_size).min(data.len());
        let chunk = &data[start..end];

        if chunk.is_empty() {
            break;
        }

        let data_checksum = calculate_checksum(chunk);

        let (final_data, header) = if let Some(pass) = password {
            // Encrypt
            let salt = mainlib::crypto::generate_salt();
            let nonce = mainlib::crypto::generate_nonce();
            let key = mainlib::crypto::derive_key_pbkdf2(pass, &salt);
            let encrypted_data = mainlib::crypto::chacha20_encrypt(chunk, &key, &nonce);

            let header = PartHeader::new_v2(
                part_num,
                num_parts,
                encrypted_data.len() as u64,
                original_size,
                data_checksum,
                original_checksum,
                salt,
                nonce,
            );

            (encrypted_data, header)
        } else {
            // No encryption
            let header = PartHeader::new_v1(
                part_num,
                num_parts,
                chunk.len() as u64,
                original_size,
                data_checksum,
                original_checksum,
            );

            (chunk.to_vec(), header)
        };

        let path = output_dir.join(format!("test.part{:03}", part_num));
        let mut file = fs::File::create(&path).unwrap();
        use std::io::Write;
        file.write_all(&header.to_bytes()).unwrap();
        file.write_all(&final_data).unwrap();

        paths.push(path);
    }

    paths
}

#[test]
fn test_split_load_reconstruct_unencrypted() {
    let temp_dir = TempDir::new().unwrap();
    let original_data = b"Hello, World! This is a test of the split and load functionality without encryption.";

    // Split into 3 parts without encryption
    let paths = split_and_encrypt(original_data, 3, None, temp_dir.path());
    assert_eq!(paths.len(), 3);

    // Load parts using local loader (simulating mounterlib)
    let parts = mounterlib::download::local::load_all_as_map(&paths, false).unwrap();
    assert_eq!(parts.len(), 3);

    // Reconstruct
    let reconstructed = mounterlib::reconstruct::rebuild_from_parts(parts, None, true, false).unwrap();
    assert_eq!(reconstructed.as_slice(), original_data);
}

#[test]
fn test_split_load_reconstruct_encrypted() {
    let temp_dir = TempDir::new().unwrap();
    let original_data = b"Secret message that should be encrypted during transmission!";
    let password = "super_secret_password";

    // Split into 3 parts with encryption
    let paths = split_and_encrypt(original_data, 3, Some(password), temp_dir.path());
    assert_eq!(paths.len(), 3);

    // Load parts
    let parts = mounterlib::download::local::load_all_as_map(&paths, false).unwrap();
    assert_eq!(parts.len(), 3);

    // Verify parts are encrypted (v2 headers)
    for (_, (header, _)) in &parts {
        assert_eq!(header.version, mainlib::HEADER_VERSION_V2);
        assert!(header.is_encrypted());
    }

    // Reconstruct with correct password
    let reconstructed = mounterlib::reconstruct::rebuild_from_parts(
        parts.clone(),
        Some(password),
        true,
        false,
    )
    .unwrap();
    assert_eq!(reconstructed.as_slice(), original_data);

    // Try with wrong password - should fail
    let result = mounterlib::reconstruct::rebuild_from_parts(
        parts.clone(),
        Some("wrong_password"),
        true,
        false,
    );
    assert!(result.is_err());

    // Try without password - should fail
    let result = mounterlib::reconstruct::rebuild_from_parts(parts, None, true, false);
    assert!(result.is_err());
}

#[test]
fn test_split_load_reconstruct_large_file() {
    let temp_dir = TempDir::new().unwrap();
    // Create a 1MB test file
    let original_data = vec![0xAAu8; 1024 * 1024];
    let password = "test_password";

    // Split into 10 parts with encryption
    let paths = split_and_encrypt(&original_data, 10, Some(password), temp_dir.path());
    assert_eq!(paths.len(), 10);

    // Load and reconstruct
    let parts = mounterlib::download::local::load_all_as_map(&paths, false).unwrap();
    let reconstructed =
        mounterlib::reconstruct::rebuild_from_parts(parts, Some(password), true, false).unwrap();

    assert_eq!(reconstructed.len(), original_data.len());
    assert_eq!(reconstructed, original_data);
}

#[test]
fn test_encrypted_parts_different_salts() {
    let temp_dir = TempDir::new().unwrap();
    let original_data = b"Test data to verify different salts per part";
    let password = "same_password";

    // Split into 3 parts
    let paths = split_and_encrypt(original_data, 3, Some(password), temp_dir.path());
    let parts = mounterlib::download::local::load_all_as_map(&paths, false).unwrap();

    // Extract salts from all parts
    let salts: Vec<[u8; 16]> = parts.values().map(|(header, _)| header.salt).collect();

    // Verify all salts are different (unique per part)
    assert_eq!(salts.len(), 3);
    assert_ne!(salts[0], salts[1]);
    assert_ne!(salts[1], salts[2]);
    assert_ne!(salts[0], salts[2]);

    // But reconstruction should still work
    let reconstructed =
        mounterlib::reconstruct::rebuild_from_parts(parts, Some(password), true, false).unwrap();
    assert_eq!(reconstructed.as_slice(), original_data);
}

#[test]
fn test_backward_compatibility_v1_and_v2() {
    let temp_dir = TempDir::new().unwrap();
    let part1_data = b"First part unencrypted";
    let part2_data = b"Second part encrypted";
    let password = "password123";

    let original_data = [part1_data.as_slice(), part2_data.as_slice()].concat();

    // Create part 0 without encryption (v1)
    let data_checksum1 = calculate_checksum(part1_data);
    let original_checksum = calculate_checksum(&original_data);
    let header1 = PartHeader::new_v1(
        0,
        2,
        part1_data.len() as u64,
        original_data.len() as u64,
        data_checksum1,
        original_checksum,
    );

    let path1 = temp_dir.path().join("test.part000");
    let mut file1 = fs::File::create(&path1).unwrap();
    use std::io::Write;
    file1.write_all(&header1.to_bytes()).unwrap();
    file1.write_all(part1_data).unwrap();

    // Create part 1 with encryption (v2)
    let salt2 = mainlib::crypto::generate_salt();
    let nonce2 = mainlib::crypto::generate_nonce();
    let key2 = mainlib::crypto::derive_key_pbkdf2(password, &salt2);
    let encrypted2 = mainlib::crypto::chacha20_encrypt(part2_data, &key2, &nonce2);
    let data_checksum2 = calculate_checksum(part2_data);

    let header2 = PartHeader::new_v2(
        1,
        2,
        encrypted2.len() as u64,
        original_data.len() as u64,
        data_checksum2,
        original_checksum,
        salt2,
        nonce2,
    );

    let path2 = temp_dir.path().join("test.part001");
    let mut file2 = fs::File::create(&path2).unwrap();
    file2.write_all(&header2.to_bytes()).unwrap();
    file2.write_all(&encrypted2).unwrap();

    // Load both parts
    let parts = mounterlib::download::local::load_all_as_map(&[path1, path2], false).unwrap();

    // Verify we have both versions
    assert_eq!(parts.get(&0).unwrap().0.version, mainlib::HEADER_VERSION_V1);
    assert_eq!(parts.get(&1).unwrap().0.version, mainlib::HEADER_VERSION_V2);

    // Reconstruct with password (needed for part 1)
    let reconstructed =
        mounterlib::reconstruct::rebuild_from_parts(parts, Some(password), true, false).unwrap();
    assert_eq!(reconstructed, original_data);
}

