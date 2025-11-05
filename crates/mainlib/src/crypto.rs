//! Cryptographic primitives for fragment encryption

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

/// ChaCha20 quarter round operation
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Generate a single ChaCha20 block
fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut state = [0u32; 16];

    // ChaCha20 constants: "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key (32 bytes = 8 u32)
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }

    // Counter
    state[12] = counter;

    // Nonce (12 bytes = 3 u32)
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    let mut working_state = state;

    // 20 rounds (10 iterations of double-round)
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut working_state, 0, 4, 8, 12);
        quarter_round(&mut working_state, 1, 5, 9, 13);
        quarter_round(&mut working_state, 2, 6, 10, 14);
        quarter_round(&mut working_state, 3, 7, 11, 15);

        // Diagonal rounds
        quarter_round(&mut working_state, 0, 5, 10, 15);
        quarter_round(&mut working_state, 1, 6, 11, 12);
        quarter_round(&mut working_state, 2, 7, 8, 13);
        quarter_round(&mut working_state, 3, 4, 9, 14);
    }

    // Add original state
    for i in 0..16 {
        working_state[i] = working_state[i].wrapping_add(state[i]);
    }

    // Convert to bytes
    let mut output = [0u8; 64];
    for i in 0..16 {
        let bytes = working_state[i].to_le_bytes();
        output[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    output
}

/// Encrypt data with ChaCha20
pub fn chacha20_encrypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    let mut counter = 0u32;

    for chunk in data.chunks(64) {
        let keystream = chacha20_block(key, nonce, counter);

        for (i, &byte) in chunk.iter().enumerate() {
            output.push(byte ^ keystream[i]);
        }

        counter += 1;
    }

    output
}

/// Decrypt data with ChaCha20 (same as encrypt, since XOR is reversible)
pub fn chacha20_decrypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    chacha20_encrypt(data, key, nonce)
}

/// Derive a 32-byte key from a password and salt using PBKDF2-HMAC-SHA256
/// Uses 100,000 iterations for security
pub fn derive_key_pbkdf2(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, 100_000, &mut key)
        .expect("PBKDF2 derivation failed");
    key
}

/// Generate a random salt for key derivation
pub fn generate_salt() -> [u8; 16] {
    rand::random()
}

/// Generate a random nonce for ChaCha20
pub fn generate_nonce() -> [u8; 12] {
    rand::random()
}
