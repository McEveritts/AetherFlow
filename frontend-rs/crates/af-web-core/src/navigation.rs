use percent_encoding::percent_decode_str;
use url::Url;

pub fn safe_login_return_to(value: &str) -> String {
    if !value.starts_with('/')
        || value.starts_with("//")
        || value
            .chars()
            .any(|c| c == '\\' || c <= ' ' || c == '\u{7f}')
    {
        return "/".into();
    }
    // decodeURIComponent rejects malformed percent encodings as well as invalid UTF-8.
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
        {
            return "/".into();
        }
    }
    let Ok(decoded) = percent_decode_str(value).decode_utf8() else {
        return "/".into();
    };
    if decoded.starts_with("//") || decoded.chars().any(|c| c == '\\' || c.is_control()) {
        return "/".into();
    }
    let base = Url::parse("https://aetherflow.invalid").expect("constant origin");
    match base.join(value) {
        Ok(url) if url.origin() == base.origin() && !url.path().starts_with("//") => {
            format!(
                "{}{}{}",
                url.path(),
                url.query().map(|q| format!("?{q}")).unwrap_or_default(),
                url.fragment().map(|f| format!("#{f}")).unwrap_or_default()
            )
        }
        _ => "/".into(),
    }
}

pub fn safe_oidc_redirect(value: &str) -> bool {
    if value.starts_with('/') {
        return !value.starts_with("//")
            && !value.contains('\\')
            && !value.chars().any(char::is_control)
            && !value.contains('#')
            && safe_login_return_to(value) == value;
    }
    if value.trim() != value
        || value.contains('#')
        || value.chars().any(|c| c <= ' ' || c == '\u{7f}')
        || value.split('?').next().unwrap_or("").contains('\\')
    {
        return false;
    }
    // Reject an explicit empty userinfo section too (URL::username alone cannot detect it).
    if value
        .split("://")
        .nth(1)
        .and_then(|s| s.split(['/', '?', '#']).next())
        .is_some_and(|s| s.contains('@'))
    {
        return false;
    }
    Url::parse(value).is_ok_and(|u| {
        u.has_host()
            && u.username().is_empty()
            && u.password().is_none()
            && (u.scheme() == "https"
                || (u.scheme() == "http"
                    && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permits_local_paths_and_authorization_continuations() {
        for s in [
            "/callback",
            "/callback?state=test",
            "/",
            "/?tab=services#logs",
            "/api/v1/auth/oidc/authorize?client_id=x",
            "/a/../b",
            "/q?search=hello%20world",
        ] {
            assert_ne!(safe_login_return_to(s), "", "{s}");
        }
        assert_eq!(safe_login_return_to("/a/../b"), "/b");
    }
    #[test]
    fn rejects_open_redirect_and_control_variants() {
        for s in [
            "",
            "https://evil.com",
            "//evil.com",
            "/\\evil",
            "/%2fexample.com",
            "/%5cevil.com",
            "/%00a",
            "/%0d%0a",
            "/bad path",
            "/%",
            "/%ff",
            "/a/..//evil.com",
        ] {
            assert_eq!(safe_login_return_to(s), "/", "{s}");
        }
    }
    #[test]
    fn oidc_callbacks_are_strict() {
        for s in [
            "/callback",
            "/callback?state=example%20value",
            "https://app.example/cb",
            "http://localhost:123/cb",
            "http://127.0.0.1/cb",
            "http://[::1]/cb",
        ] {
            assert!(safe_oidc_redirect(s), "{s}");
        }
        for s in [
            "javascript:alert(1)",
            "//evil.com",
            "http://evil.com",
            "https://user@evil.com/cb",
            "https://@evil.com/cb",
            "https://good/cb#x",
            " https://good/cb",
            "/\\evil.com",
            "/%2fevil.com",
            "/callback\n",
        ] {
            assert!(!safe_oidc_redirect(s), "{s}");
        }
    }
}
