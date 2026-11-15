use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const FEISTEL_DOMAIN: &[u8] = b"AetherFlow-LibreSpeed-ULID-Obfuscation-v1";

/// Generates a canonical 26-character Crockford Base32 ULID:
/// 48-bit big-endian Unix millisecond timestamp + 80-bit `OsRng` entropy.
pub fn generate_ulid() -> String {
    let ms = Utc::now().timestamp_millis().max(0) as u64;
    generate_ulid_at_ms(ms)
}

/// Generates a canonical 26-character Crockford Base32 ULID at a specific
/// Unix millisecond timestamp with 80 bits of `OsRng` entropy.
pub fn generate_ulid_at_ms(ms: u64) -> String {
    let mut rand_bytes = [0u8; 10];
    OsRng.fill_bytes(&mut rand_bytes);

    let mut raw = [0u8; 16];
    let ms_bytes = ms.to_be_bytes();
    raw[..6].copy_from_slice(&ms_bytes[2..8]);
    raw[6..].copy_from_slice(&rand_bytes);

    encode_u128(u128::from_be_bytes(raw))
}

pub fn encode_u128(mut value: u128) -> String {
    let mut out = [b'0'; 26];
    for slot in out.iter_mut().rev() {
        let idx = (value & 0x1F) as usize;
        *slot = CROCKFORD_ALPHABET[idx];
        value >>= 5;
    }
    String::from_utf8(out.to_vec()).expect("Crockford alphabet is valid UTF-8")
}

pub fn decode_ulid(input: &str) -> Option<u128> {
    if input.len() != 26 || !input.is_ascii() {
        return None;
    }
    let mut acc: u128 = 0;
    for (idx, b) in input.bytes().enumerate() {
        let digit = crockford_value(b)?;
        if idx == 0 && digit > 7 {
            // Top 2 bits of 130-bit Base32 must be zero to fit in 128 bits.
            return None;
        }
        acc = (acc << 5) | u128::from(digit);
    }
    Some(acc)
}

pub fn canonicalize_ulid(input: &str) -> Option<String> {
    decode_ulid(input).map(encode_u128)
}

fn crockford_value(byte: u8) -> Option<u8> {
    let mapped = match byte.to_ascii_uppercase() {
        b'0' | b'O' => 0,
        b'1' | b'I' | b'L' => 1,
        b'2' => 2,
        b'3' => 3,
        b'4' => 4,
        b'5' => 5,
        b'6' => 6,
        b'7' => 7,
        b'8' => 8,
        b'9' => 9,
        b'A' => 10,
        b'B' => 11,
        b'C' => 12,
        b'D' => 13,
        b'E' => 14,
        b'F' => 15,
        b'G' => 16,
        b'H' => 17,
        b'J' => 18,
        b'K' => 19,
        b'M' => 20,
        b'N' => 21,
        b'P' => 22,
        b'Q' => 23,
        b'R' => 24,
        b'S' => 25,
        b'T' => 26,
        b'V' => 27,
        b'W' => 28,
        b'X' => 29,
        b'Y' => 30,
        b'Z' => 31,
        _ => return None,
    };
    Some(mapped)
}

fn round_prf(key: &[u8; 32], round: u8, right: u64) -> u64 {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(FEISTEL_DOMAIN);
    mac.update(&[round]);
    mac.update(&right.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    u64::from_be_bytes(digest[..8].try_into().expect("8-byte slice"))
}

/// Deterministically and reversibly obfuscates a 26-char Crockford Base32 ULID
/// using a keyed 4-round balanced 64+64 HMAC-SHA256 Feistel permutation, hiding
/// timestamp ordering and preventing unauthenticated inversion while remaining
/// invertible across daemon restarts via the SQLite vault's `obfuscation_key`.
pub fn obfuscate_ulid(canonical: &str, key: &[u8; 32]) -> String {
    let Some(val) = decode_ulid(canonical) else {
        return canonical.to_string();
    };
    let mut left = (val >> 64) as u64;
    let mut right = val as u64;

    for round in 0..4u8 {
        let next_right = left ^ round_prf(key, round, right);
        left = right;
        right = next_right;
    }

    let combined = (u128::from(left) << 64) | u128::from(right);
    encode_u128(combined)
}

pub fn deobfuscate_ulid(obfuscated: &str, key: &[u8; 32]) -> Option<String> {
    let val = decode_ulid(obfuscated)?;
    let mut left = (val >> 64) as u64;
    let mut right = val as u64;

    for round in (0..4u8).rev() {
        let prev_left = right ^ round_prf(key, round, left);
        right = left;
        left = prev_left;
    }

    let combined = (u128::from(left) << 64) | u128::from(right);
    Some(encode_u128(combined))
}

/// Resolves an incoming external ID (from `/results?id=...` or `/stats`) into
/// the stored canonical ULID. When obfuscation is enabled, only valid
/// obfuscated IDs under `key` reverse cleanly (preventing sequential ULID
/// enumeration and offline timestamp recovery).
pub fn resolve_id(raw_id: &str, obfuscation_enabled: bool, key: &[u8; 32]) -> Option<String> {
    let trimmed = raw_id.trim();
    if trimmed.is_empty() {
        return None;
    }
    if obfuscation_enabled {
        deobfuscate_ulid(trimmed, key)
    } else {
        canonicalize_ulid(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generates_valid_unique_ulids() {
        let mut seen = HashSet::new();
        for _ in 0..256 {
            let id = generate_ulid();
            assert_eq!(id.len(), 26);
            assert!(decode_ulid(&id).is_some());
            assert!(seen.insert(id));
        }
    }

    #[test]
    fn obfuscation_round_trips_hides_timestamp_and_requires_secret_key() {
        let key_a = [0x42u8; 32];
        let key_b = [0x99u8; 32];
        let u1 = generate_ulid_at_ms(1_700_000_000_000);
        let u2 = generate_ulid_at_ms(1_700_000_000_000);
        assert_eq!(&u1[..6], &u2[..6]);

        let ob1 = obfuscate_ulid(&u1, &key_a);
        let ob2 = obfuscate_ulid(&u2, &key_a);
        assert_ne!(ob1, u1);
        assert_ne!(ob1, ob2);
        assert_ne!(&ob1[..6], &ob2[..6]);

        assert_eq!(deobfuscate_ulid(&ob1, &key_a).as_deref(), Some(u1.as_str()));
        assert_ne!(deobfuscate_ulid(&ob1, &key_b).as_deref(), Some(u1.as_str()));
        assert_eq!(resolve_id(&ob1, true, &key_a).as_deref(), Some(u1.as_str()));
        assert_ne!(resolve_id(&ob1, true, &key_b).as_deref(), Some(u1.as_str()));
        assert_ne!(resolve_id(&u1, true, &key_a).as_deref(), Some(u1.as_str()));
        assert_eq!(resolve_id(&u1, false, &key_a).as_deref(), Some(u1.as_str()));
    }

    #[test]
    fn rejects_invalid_or_overflowing_ulids() {
        assert!(decode_ulid("short").is_none());
        assert!(decode_ulid("80000000000000000000000000").is_none());
        assert!(decode_ulid("01J0000000000000000000000U").is_none());
        assert_eq!(
            canonicalize_ulid("01j000000000000000000000ol"),
            Some("01J00000000000000000000001".to_string())
        );
    }
}
