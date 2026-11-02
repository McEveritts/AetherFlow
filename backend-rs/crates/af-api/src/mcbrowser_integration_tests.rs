use crate::auth::{csrf_middleware, AuthUser};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{middleware, Extension, Router};
use tower::ServiceExt;

#[tokio::test]
async fn mcbrowser_routes_require_authentication_in_both_api_versions() {
    for prefix in ["/api/v1/auth", "/api/auth"] {
        for (method, endpoint) in [
            ("GET", "entries"),
            ("GET", "download"),
            ("GET", "preview"),
            ("POST", "directory"),
            ("POST", "rename"),
            ("PUT", "upload"),
            ("DELETE", "entry"),
            ("GET", "policy"),
            ("PUT", "policy/1"),
            ("GET", "preferences"),
            ("PUT", "preferences"),
            ("GET", "usage"),
            ("GET", "search"),
            ("POST", "copy"),
            ("POST", "delete-recursive"),
            ("GET", "content"),
            ("PUT", "content"),
            ("POST", "file"),
            ("GET", "info"),
            ("POST", "archive"),
            ("POST", "archive-ticket"),
            ("GET", "archive/fixture"),
            ("GET", "uploads"),
            ("POST", "uploads"),
            ("HEAD", "uploads/fixture"),
            ("PATCH", "uploads/fixture"),
            ("DELETE", "uploads/fixture"),
            ("GET", "shares"),
            ("POST", "shares"),
            ("DELETE", "shares/fixture"),
            ("GET", "media"),
            ("GET", "media-info"),
            ("GET", "thumbnail"),
            ("GET", "subtitles"),
            ("GET", "subtitle"),
            ("GET", "csv"),
            ("GET", "epub"),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(format!("{prefix}/mcbrowser/{endpoint}?path=file.txt"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"path":"folder","from":"a","to":"b"}"#))
                .unwrap();
            let response = crate::routes::build_router()
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {endpoint}"
            );
        }
    }
}

#[tokio::test]
async fn mcbrowser_mutations_inherit_cookie_csrf_protection() {
    if std::env::var("CSRF_DISABLED").is_ok_and(|value| value.eq_ignore_ascii_case("true")) {
        return;
    }
    let user = AuthUser {
        user_id: 1,
        username: "fixture".to_owned(),
        role: "user".to_owned(),
        jti: "fixture".to_owned(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    for (method, endpoint) in [
        ("POST", "directory"),
        ("POST", "rename"),
        ("PUT", "upload"),
        ("DELETE", "entry"),
        ("PUT", "policy/1"),
        ("PUT", "preferences"),
        ("POST", "copy"),
        ("POST", "delete-recursive"),
        ("PUT", "content"),
        ("POST", "file"),
        ("POST", "archive"),
        ("POST", "archive-ticket"),
        ("POST", "uploads"),
        ("PATCH", "uploads/fixture"),
        ("DELETE", "uploads/fixture"),
        ("POST", "shares"),
        ("DELETE", "shares/fixture"),
    ] {
        let router = Router::new()
            .merge(crate::mcbrowser::router())
            .layer(middleware::from_fn(csrf_middleware))
            .layer(Extension(user.clone()));
        let request = Request::builder()
            .method(method)
            .uri(format!("/mcbrowser/{endpoint}?path=file.txt"))
            .header("content-type", "application/json")
            .header("cookie", "aetherflow_session=fixture")
            .body(Body::from(r#"{"path":"folder","from":"a","to":"b"}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{method} {endpoint}"
        );
    }
}
