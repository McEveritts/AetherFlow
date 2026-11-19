//! Redaction for diagnostic messages that may be persisted or returned to clients.

use std::borrow::Cow;

const SECRET_LABELS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api-key",
    "apikey",
    "private-key",
    "client-secret",
];

/// Removes entire credential-bearing lines so quoted and structured values cannot be
/// partially exposed in an error receipt. Ordinary diagnostic lines are preserved.
pub fn redact_diagnostic(message: &str) -> Cow<'_, str> {
    let sensitive = |line: &str| {
        let lower = line.to_ascii_lowercase().replace('_', "-");
        let credentials_url = lower.match_indices("://").any(|(start, _)| {
            let authority = lower[start + 3..]
                .split(|c: char| c.is_whitespace() || matches!(c, '/' | '?' | '#'))
                .next()
                .unwrap_or_default();
            authority.contains('@')
        });
        credentials_url
            || SECRET_LABELS.iter().any(|label| {
                lower.match_indices(label).any(|(offset, _)| {
                    let after = lower[offset + label.len()..]
                        .trim_start_matches(['"', '\''])
                        .trim_start();
                    let assignment = after.starts_with(['=', ':']) && !after[1..].trim().is_empty();
                    let flag = lower[..offset].ends_with("--") && !after.is_empty();
                    assignment || flag
                })
            })
    };
    if !message.lines().any(sensitive) {
        return Cow::Borrowed(message);
    }
    Cow::Owned(
        message
            .split_inclusive('\n')
            .map(|line| {
                if sensitive(line.trim_end()) {
                    if line.ends_with('\n') {
                        "[REDACTED]\n"
                    } else {
                        "[REDACTED]"
                    }
                } else {
                    line
                }
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_redacts_url_headers_and_quoted_assignments() {
        let raw = "updater failed\nAuthorization: Bearer ABC\nhttps://user:pass@example.com\n{\"GH_TOKEN\":\"XYZ\"}";
        assert_eq!(
            redact_diagnostic(raw),
            "updater failed\n[REDACTED]\n[REDACTED]\n[REDACTED]"
        );
    }
}
