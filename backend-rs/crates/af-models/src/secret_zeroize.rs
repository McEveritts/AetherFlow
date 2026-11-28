//! Zeroize-on-drop secret containers (`SEC-05`).
//!
//! [`SecretString`] and [`SecretBytes`] own a heap buffer holding key material,
//! tokens, PEMs or passwords. On [`Drop`] (and on explicit [`SecretBytes::zeroize`]
//! / [`SecretString::zeroize`]) the **entire** `0..capacity` backing allocation is
//! overwritten with zeros — both the initialized `0..len` prefix and the spare
//! `len..capacity` tail exposed by [`Vec::spare_capacity_mut`] — using
//! [`core::ptr::write_volatile`] followed by
//! [`compiler_fence(Ordering::SeqCst)`](core::sync::atomic::compiler_fence), so the
//! optimizer cannot elide the wipe as a dead store.
//!
//! Design constraints:
//! - **Zero new dependencies** (no `zeroize` crate) so `af-models` keeps compiling
//!   for `wasm32-unknown-unknown`.
//! - `fmt::Debug` prints `"[REDACTED]"`; `Display` and `Serialize` are deliberately
//!   **not** implemented, so a secret can only leave the wrapper through an explicit
//!   [`expose_secret`](SecretString::expose_secret) call that is easy to audit.
//! - Equality is constant-time over byte contents (lengths are treated as public).
//! - No mutation API is exposed: growing a `String`/`Vec` reallocates and would
//!   leave an unzeroized copy of the old allocation behind.
//!
//! Limits: this protects the buffer owned by the wrapper. Copies made before the
//! value was wrapped (e.g. a deserializer's scratch buffer, a `String` that was
//! reallocated while being built, or a slice copied out of `expose_secret`) are
//! outside its control. Wrap secrets as early as possible.

use core::fmt;
use core::mem::MaybeUninit;
use core::sync::atomic::{compiler_fence, Ordering};

const REDACTED: &str = "[REDACTED]";

/// Overwrites the whole `0..capacity` allocation of `buf` with zeros and then
/// clears it (`len == 0`, capacity retained).
///
/// The initialized prefix and the spare tail are each wiped with volatile
/// writes; a `SeqCst` compiler fence orders the wipe before any later
/// deallocation.
pub(crate) fn zeroize_vec_full_capacity(buf: &mut Vec<u8>) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive `&mut u8`.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    for slot in buf.spare_capacity_mut().iter_mut() {
        // SAFETY: `slot` is a valid, aligned, exclusive `&mut MaybeUninit<u8>`;
        // writing an initialized value into uninitialized storage is always sound.
        unsafe { core::ptr::write_volatile(slot, MaybeUninit::new(0)) };
    }
    compiler_fence(Ordering::SeqCst);
    buf.clear();
    compiler_fence(Ordering::SeqCst);
}

/// Zeroizing owner of secret UTF-8 text.
pub struct SecretString {
    inner: String,
}

impl SecretString {
    /// Takes ownership of `value` without copying it.
    pub fn new(value: String) -> Self {
        Self { inner: value }
    }

    /// Returns the secret text. Every call site is an explicit, auditable exposure.
    pub fn expose_secret(&self) -> &str {
        &self.inner
    }

    /// Length of the secret in bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Wipes the full backing allocation now, leaving an empty secret.
    pub fn zeroize(&mut self) {
        // SAFETY: zero bytes are valid UTF-8 and the vector is cleared before the
        // `String` can be observed again, so the UTF-8 invariant is preserved.
        zeroize_vec_full_capacity(unsafe { self.inner.as_mut_vec() });
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Default for SecretString {
    fn default() -> Self {
        Self::new(String::new())
    }
}

/// Cloning allocates an independent buffer that is itself zeroized on drop.
/// Prefer moving secrets; every clone is one more short-lived copy in memory.
impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        crate::constant_time_eq(self.inner.as_bytes(), other.inner.as_bytes())
    }
}

impl Eq for SecretString {}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl<'de> serde::Deserialize<'de> for SecretString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// Zeroizing owner of secret binary data.
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// Takes ownership of `value` without copying it.
    pub fn new(value: Vec<u8>) -> Self {
        Self { inner: value }
    }

    /// Returns the secret bytes. Every call site is an explicit, auditable exposure.
    pub fn expose_secret(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Wipes the full backing allocation now, leaving an empty secret.
    pub fn zeroize(&mut self) {
        zeroize_vec_full_capacity(&mut self.inner);
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Default for SecretBytes {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

/// Cloning allocates an independent buffer that is itself zeroized on drop.
/// Prefer moving secrets; every clone is one more short-lived copy in memory.
impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        crate::constant_time_eq(&self.inner, &other.inner)
    }
}

impl Eq for SecretBytes {}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(value: &[u8]) -> Self {
        Self::new(value.to_vec())
    }
}

impl From<SecretString> for SecretBytes {
    /// Moves the allocation without copying; `SecretString`'s own drop then
    /// wipes an empty buffer.
    fn from(mut value: SecretString) -> Self {
        Self::new(core::mem::take(&mut value.inner).into_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for SecretBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<u8>::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads the full `0..capacity` region of a vector whose spare capacity has
    /// been initialized by `zeroize_vec_full_capacity`.
    fn full_capacity_bytes(buf: &mut Vec<u8>) -> Vec<u8> {
        let cap = buf.capacity();
        // SAFETY: every byte in `0..cap` was initialized by the volatile wipe and
        // `u8` has no invalid bit patterns.
        unsafe { buf.set_len(cap) };
        let copy = buf.clone();
        buf.clear();
        copy
    }

    fn assert_all_zero(bytes: &[u8]) {
        assert!(
            bytes.iter().all(|b| *b == 0),
            "non-zero byte left in backing buffer"
        );
    }

    #[test]
    fn wipes_initialized_prefix_and_spare_capacity() {
        let mut buf = Vec::with_capacity(256);
        buf.extend(std::iter::repeat_n(0xA5_u8, 200));
        let cap = buf.capacity();
        zeroize_vec_full_capacity(&mut buf);
        assert!(buf.is_empty());
        assert_eq!(
            buf.capacity(),
            cap,
            "allocation must be retained, not freed"
        );
        let bytes = full_capacity_bytes(&mut buf);
        assert_eq!(bytes.len(), cap);
        assert_all_zero(&bytes);
    }

    #[test]
    fn wipes_stale_bytes_left_in_spare_capacity_after_truncate_and_clear() {
        // truncate(): secret bytes beyond `len` remain in spare capacity.
        let mut truncated = b"super-secret-token-value".to_vec();
        let ptr_before = truncated.as_ptr();
        truncated.truncate(5);
        let mut secret = SecretBytes::new(truncated);
        assert_eq!(secret.expose_secret(), b"super");
        secret.zeroize();
        assert!(secret.is_empty());
        assert_eq!(secret.inner.as_ptr(), ptr_before);
        assert_all_zero(&full_capacity_bytes(&mut secret.inner));

        // clear(): len == 0 but the full allocation still holds secret bytes.
        let mut cleared = String::from("synthetic-cleared-material-payload-33b");
        cleared.clear();
        let mut secret = SecretString::new(cleared);
        assert!(secret.is_empty());
        secret.zeroize();
        let inner = unsafe { secret.inner.as_mut_vec() };
        assert!(inner.capacity() >= 33);
        assert_all_zero(&full_capacity_bytes(inner));
    }

    #[test]
    fn drop_runs_full_capacity_wipe_on_both_wrappers() {
        // Drop delegates to `zeroize`; exercise drop with spare capacity and
        // zero-capacity buffers to make sure neither path misbehaves.
        let mut s = String::with_capacity(1024);
        s.push_str("hunter2");
        drop(SecretString::new(s));
        drop(SecretString::default());
        let mut v = Vec::with_capacity(4096);
        v.extend_from_slice(b"\x00\x01\x02secret");
        drop(SecretBytes::new(v));
        drop(SecretBytes::default());

        // `Drop` is exactly `zeroize()`; run that path on a live value whose
        // allocation is retained so the wiped storage can be inspected.
        let mut s = String::with_capacity(64);
        s.push_str("jwt.payload.signature");
        let mut secret = SecretString::new(s);
        secret.zeroize();
        assert_all_zero(&full_capacity_bytes(unsafe { secret.inner.as_mut_vec() }));
        // Idempotent: a second wipe (as performed by the eventual drop) is a no-op.
        secret.zeroize();
        assert!(secret.is_empty());
    }

    #[test]
    fn debug_is_redacted_and_never_leaks_contents() {
        let s = SecretString::from("p@ssw0rd-very-secret");
        let b = SecretBytes::from(&b"\xde\xad\xbe\xef"[..]);
        assert_eq!(format!("{s:?}"), "[REDACTED]");
        assert_eq!(format!("{s:#?}"), "[REDACTED]");
        assert_eq!(format!("{b:?}"), "[REDACTED]");
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            token: SecretString,
        }
        let rendered = format!("{:?}", Holder { token: s.clone() });
        assert!(!rendered.contains("p@ss"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn equality_is_content_based_and_length_sensitive() {
        assert_eq!(SecretString::from("abc"), SecretString::from("abc"));
        assert_ne!(SecretString::from("abc"), SecretString::from("abd"));
        assert_ne!(SecretString::from("abc"), SecretString::from("abc\0"));
        assert_ne!(SecretString::from(""), SecretString::from("\0"));
        assert_eq!(
            SecretBytes::from(vec![0, 255]),
            SecretBytes::from(vec![0, 255])
        );
        assert_ne!(
            SecretBytes::from(vec![0, 255]),
            SecretBytes::from(vec![0, 254])
        );
        assert_eq!(SecretBytes::default(), SecretBytes::from(Vec::new()));
    }

    #[test]
    fn accessors_clone_and_conversions() {
        let s = SecretString::new("token".to_string());
        assert_eq!(s.len(), 5);
        assert!(!s.is_empty());
        assert_eq!(s.expose_secret(), "token");
        let c = s.clone();
        assert_eq!(c, s);
        assert_ne!(c.expose_secret().as_ptr(), s.expose_secret().as_ptr());

        let s = SecretString::from("moved".to_string());
        let ptr = s.expose_secret().as_ptr();
        let b = SecretBytes::from(s);
        assert_eq!(b.expose_secret(), b"moved");
        assert_eq!(b.expose_secret().as_ptr(), ptr, "conversion must not copy");
        assert_eq!(b.len(), 5);
    }

    #[test]
    fn deserializes_without_exposing_through_debug() {
        let s: SecretString = serde_json::from_str("\"api-key-123\"").unwrap();
        assert_eq!(s.expose_secret(), "api-key-123");
        let b: SecretBytes = serde_json::from_str("[1,2,3]").unwrap();
        assert_eq!(b.expose_secret(), &[1, 2, 3]);

        #[derive(serde::Deserialize, Debug)]
        struct Settings {
            api_key: SecretString,
        }
        let settings: Settings = serde_json::from_str(r#"{"api_key":"sk-live-xyz"}"#).unwrap();
        assert_eq!(settings.api_key.expose_secret(), "sk-live-xyz");
        assert!(!format!("{settings:?}").contains("sk-live"));
    }
}
