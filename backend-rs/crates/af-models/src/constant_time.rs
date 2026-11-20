/// Compares all bytes up to the longer length without short-circuiting on
/// byte contents. Lengths are treated as public.
#[inline(never)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let a = std::hint::black_box(a);
    let b = std::hint::black_box(b);
    let mut diff = a.len() ^ b.len();
    for index in 0..a.len().max(b.len()) {
        let left = a.get(index).copied().unwrap_or(0);
        let right = b.get(index).copied().unwrap_or(0);
        diff |= usize::from(left ^ right);
    }
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn compares_content_and_lengths_including_zero_padding() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(&[0, 128, 255], &[0, 128, 255]));
        for (left, right) in [
            (&b""[..], &b"\0"[..]),
            (b"secret", b"secret\0"),
            (b"secret", b"Secret"),
            (b"secret", b"secreT"),
        ] {
            assert!(!constant_time_eq(left, right));
            assert!(!constant_time_eq(right, left));
        }
    }
}
