use super::host_resolution::{
    explicit_control_plane_host, local_control_plane_host, resolve_app_host_disposition,
    resolve_proxy_work, strip_host_port_and_dot, AppHostResolution, PROXY_AUTH_BLOCKING_LIMIT,
    PROXY_RESOLVE_TIMEOUT,
};
use super::proxy_helpers::{
    canonical_forwarded_headers, forward_proxy_http_headers, internal_domain_forbidden,
    is_forwarded_header_name, is_hop_by_hop_header, is_spoofable_identity_header,
    is_strict_loopback_https_url, is_trusted_proxy_ip, is_unauth_local_lan_ip,
    librespeed_tls_client, local_domain_client_allowed, managed_app_route_unavailable,
    read_rutorrent_proxy_token, resolve_optional_authenticated_user, strip_gateway_session_cookies,
    unauth_local_lan_enabled, upstream_uses_tls, verify_proxy_basic_credentials, PROXY_HTTP_CLIENT,
    PROXY_LOOPBACK_TLS_CLIENT, PROXY_LOOPBACK_TLS_WS_CLIENT,
};
use super::rate_limit::{rate_limited_response, PROXY_BASIC_AUTH_LIMITER};
use crate::auth::api_error;
use af_runner::package_executor::{
    requires_external_app_auth as external_proxy_requires_auth, GATEWAY_APP_HEADER,
};
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::Request;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use std::net::SocketAddr;
use std::time::Duration;

pub async fn app_subdomain_proxy_middleware(req: Request, next: Next) -> Response {
    // Apache uses this header to require an application route. It cannot grant
    // access or select an upstream. The incoming Host still drives resolution.
    let managed_app = req.headers().get(GATEWAY_APP_HEADER);
    if req.uri().path().starts_with("/.well-known/acme-challenge/") {
        if managed_app.is_some() {
            return managed_app_route_unavailable();
        }
        return next.run(req).await;
    }

    let peer_ip_opt = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    if managed_app.is_some() && !peer_ip_opt.is_some_and(|peer| peer.to_canonical().is_loopback()) {
        return managed_app_route_unavailable();
    }
    let trust_forwarded = peer_ip_opt.is_some_and(is_trusted_proxy_ip);

    let raw_host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let clean_host = strip_host_port_and_dot(&raw_host);

    let is_internal_aether_local = clean_host.ends_with(".aether.local");
    // Known control-plane authorities need no DB or auth work.
    if local_control_plane_host(&clean_host)
        || (managed_app.is_none() && explicit_control_plane_host(&raw_host, &clean_host))
        || af_db::maybe_cached_control_plane_host(&clean_host)
    {
        if managed_app.is_some() {
            return managed_app_route_unavailable();
        }
        return next.run(req).await;
    }
    if is_internal_aether_local && !local_domain_client_allowed(req.headers(), peer_ip_opt) {
        return internal_domain_forbidden();
    }

    let lookup_host = raw_host.clone();
    let Some(disposition) =
        resolve_proxy_work(move || resolve_app_host_disposition(&lookup_host)).await
    else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "PROXY_RESOLUTION_UNAVAILABLE",
            "Proxy resolution unavailable",
        );
    };
    let (app_name, target_port) = match disposition {
        AppHostResolution::Proxy(app, port) => (app, port),
        AppHostResolution::DisabledExternalApp(_) => {
            return api_error(
                StatusCode::FORBIDDEN,
                "EXTERNAL_ACCESS_DISABLED",
                "External access is not enabled for this application subdomain",
            );
        }
        AppHostResolution::ControlPlane if managed_app.is_some() => {
            return managed_app_route_unavailable();
        }
        AppHostResolution::ControlPlane => return next.run(req).await,
    };
    let unauth_local_lan_bypass = is_internal_aether_local
        && unauth_local_lan_enabled()
        && peer_ip_opt.is_some_and(|peer| {
            is_unauth_local_lan_ip(&crate::ws::extract_client_ip_for_peer(
                req.headers(),
                Some(peer),
            ))
        });
    let requires_auth = external_proxy_requires_auth(&app_name) && !unauth_local_lan_bypass;
    if managed_app.is_some_and(|expected| {
        !requires_auth
            || expected.as_bytes() != app_name.as_bytes()
            || !(1..=65535).contains(&target_port)
    }) {
        return managed_app_route_unavailable();
    }
    if !(1..=65535).contains(&target_port) {
        return next.run(req).await;
    }

    let app_origin =
        crate::app_launch::managed_origin(req.headers(), &raw_host, managed_app.is_some());
    if req.uri().path() == af_models::APP_LAUNCH_EXCHANGE_PATH {
        return crate::app_launch::redeem(req, app_name, app_origin).await;
    }

    let headers = req.headers().clone();
    let auth_app = app_name.clone();
    let authenticated_user = resolve_proxy_work(move || {
        app_origin
            .and_then(|origin| crate::app_launch::authenticated_admin(&headers, &auth_app, &origin))
            .or_else(|| {
                resolve_optional_authenticated_user(&headers, peer_ip_opt)
                    .filter(|user| !requires_auth || user.role == "admin")
                    .map(|user| user.username)
            })
    })
    .await
    .flatten();
    let authenticated_user = if requires_auth
        && authenticated_user.is_none()
        && req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '))
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
    {
        let ip = peer_ip_opt.map_or_else(
            || "127.0.0.1".to_string(),
            |peer| crate::ws::extract_client_ip_for_peer(req.headers(), Some(peer)),
        );
        let Some(attempt) = PROXY_BASIC_AUTH_LIMITER.reserve(&ip) else {
            return rate_limited_response();
        };
        let headers = req.headers().clone();
        tokio::time::timeout(PROXY_RESOLVE_TIMEOUT, async move {
            let permit = PROXY_AUTH_BLOCKING_LIMIT.acquire().await.ok()?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let user = verify_proxy_basic_credentials(&headers);
                if user.is_some() {
                    PROXY_BASIC_AUTH_LIMITER.refund(&ip, attempt);
                }
                user
            })
            .await
            .ok()
            .flatten()
        })
        .await
        .ok()
        .flatten()
    } else {
        authenticated_user
    };
    if requires_auth && authenticated_user.is_none() {
        let mut response = api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Administrator authentication required",
        );
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"AetherFlow\""),
        );
        return response;
    }

    let upgrade_header = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let is_ws_upgrade = !upgrade_header.is_empty()
        && (upgrade_header.eq_ignore_ascii_case("websocket")
            || req
                .headers()
                .get(header::CONNECTION)
                .and_then(|v| v.to_str().ok())
                .map(|c| c.to_ascii_lowercase().contains("upgrade"))
                .unwrap_or(false));

    let method_str = req.method().as_str().to_string();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let pinned_client = if app_name == "librespeed" {
        match resolve_proxy_work(librespeed_tls_client).await {
            Some(Ok(client)) => client,
            result => {
                tracing::warn!(?result, "LibreSpeed upstream TLS configuration unavailable");
                return api_error(
                    StatusCode::BAD_GATEWAY,
                    "BAD_GATEWAY",
                    "LibreSpeed upstream TLS configuration unavailable",
                );
            }
        }
    } else {
        None
    };
    let rutorrent_proxy_token = if app_name == "rutorrent" {
        match resolve_proxy_work(read_rutorrent_proxy_token).await {
            Some(Ok(token)) => token,
            result => {
                tracing::warn!(?result, "ruTorrent proxy token unavailable");
                return api_error(
                    StatusCode::BAD_GATEWAY,
                    "BAD_GATEWAY",
                    "ruTorrent upstream proxy token unavailable",
                );
            }
        }
    } else {
        None
    };
    let use_tls = pinned_client.is_some()
        || (app_name != "librespeed" && upstream_uses_tls(&app_name, target_port as u16));
    let scheme = if use_tls { "https" } else { "http" };
    let target_url = format!("{scheme}://127.0.0.1:{target_port}{path_and_query}");

    let mut incoming_headers = req.headers().clone();
    if requires_auth {
        incoming_headers.remove(header::AUTHORIZATION);
    }
    strip_gateway_session_cookies(&mut incoming_headers, requires_auth);

    if is_ws_upgrade {
        if use_tls {
            if !is_strict_loopback_https_url(&target_url) {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": "bad_gateway",
                        "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                    })),
                )
                    .into_response();
            }

            let reqwest_method =
                reqwest::Method::from_bytes(method_str.as_bytes()).unwrap_or(reqwest::Method::GET);
            let mut ws_req = pinned_client
                .as_ref()
                .unwrap_or(&PROXY_LOOPBACK_TLS_WS_CLIENT)
                .request(reqwest_method, &target_url);
            ws_req = forward_proxy_http_headers(
                ws_req,
                &incoming_headers,
                &raw_host,
                peer_ip_opt,
                trust_forwarded,
            );
            ws_req = ws_req.header(reqwest::header::CONNECTION, "Upgrade");
            if let Some(ref user) = authenticated_user {
                ws_req = ws_req.header("X-Aetherflow-User", user);
            }
            if let Some(ref token) = rutorrent_proxy_token {
                ws_req = ws_req.header("X-Aetherflow-Rutorrent-Token", token);
            }

            let upstream_resp = match tokio::time::timeout(Duration::from_secs(15), ws_req.send())
                .await
            {
                Ok(Ok(resp)) => resp,
                Ok(Err(err)) => {
                    tracing::warn!(
                        app = %app_name,
                        host = %raw_host,
                        port = target_port,
                        error = %err,
                        "subdomain reverse proxy TLS websocket upstream error"
                    );
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(serde_json::json!({
                            "error": "bad_gateway",
                            "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                        })),
                    )
                        .into_response();
                }
                Err(_) => {
                    return (
                        StatusCode::GATEWAY_TIMEOUT,
                        Json(serde_json::json!({
                            "error": "gateway_timeout",
                            "message": format!("Upstream service {} on port {} upgrade timed out.", app_name, target_port),
                        })),
                    )
                        .into_response();
                }
            };

            if upstream_resp.status() == reqwest::StatusCode::SWITCHING_PROTOCOLS {
                let resp_headers_clone = upstream_resp.headers().clone();
                let client_upgrade = hyper::upgrade::on(req);
                let upstream_upgrade = upstream_resp.upgrade();

                tokio::spawn(async move {
                    match tokio::try_join!(
                        async move { client_upgrade.await.map_err(std::io::Error::other) },
                        async move { upstream_upgrade.await.map_err(std::io::Error::other) }
                    ) {
                        Ok((client_upgraded, mut upstream_upgraded)) => {
                            let mut client_io = hyper_util::rt::TokioIo::new(client_upgraded);
                            let _ = tokio::io::copy_bidirectional(
                                &mut client_io,
                                &mut upstream_upgraded,
                            )
                            .await;
                        }
                        Err(err) => {
                            tracing::debug!(error = %err, "subdomain TLS websocket upgrade tunnel closed");
                        }
                    }
                });

                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                let out_headers = response.headers_mut();
                for (k, v) in resp_headers_clone.iter() {
                    if let (Ok(hk), Ok(hv)) = (
                        HeaderName::from_bytes(k.as_str().as_bytes()),
                        HeaderValue::from_bytes(v.as_bytes()),
                    ) {
                        out_headers.append(hk, hv);
                    }
                }
                if !out_headers.contains_key(header::UPGRADE) {
                    if let Ok(up_hv) = HeaderValue::from_str(&upgrade_header) {
                        out_headers.insert(header::UPGRADE, up_hv);
                    }
                }
                if !out_headers.contains_key(header::CONNECTION) {
                    out_headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
                }
                return response;
            } else {
                let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                    .unwrap_or(StatusCode::BAD_GATEWAY);
                let resp_headers_clone = upstream_resp.headers().clone();
                let stream = upstream_resp.bytes_stream();
                let mut response = Response::new(Body::from_stream(stream));
                *response.status_mut() = status;
                let out_headers = response.headers_mut();
                for (k, v) in resp_headers_clone.iter() {
                    if is_hop_by_hop_header(k.as_str()) {
                        continue;
                    }
                    if let (Ok(hk), Ok(hv)) = (
                        HeaderName::from_bytes(k.as_str().as_bytes()),
                        HeaderValue::from_bytes(v.as_bytes()),
                    ) {
                        out_headers.append(hk, hv);
                    }
                }
                return response;
            }
        }

        let tcp_stream = match tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(("127.0.0.1", target_port as u16)),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                tracing::warn!(
                    app = %app_name,
                    host = %raw_host,
                    port = target_port,
                    error = %err,
                    "subdomain reverse proxy websocket upstream connect error"
                );
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": "bad_gateway",
                        "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                    })),
                )
                    .into_response();
            }
            Err(_) => {
                tracing::warn!(
                    app = %app_name,
                    host = %raw_host,
                    port = target_port,
                    "subdomain reverse proxy websocket upstream connect timeout"
                );
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(serde_json::json!({
                        "error": "gateway_timeout",
                        "message": format!("Upstream service {} on port {} timed out connecting.", app_name, target_port),
                    })),
                )
                    .into_response();
            }
        };

        let io = hyper_util::rt::TokioIo::new(tcp_stream);
        let (mut sender, conn) = match tokio::time::timeout(
            Duration::from_secs(10),
            hyper::client::conn::http1::handshake(io),
        )
        .await
        {
            Ok(Ok(pair)) => pair,
            Ok(Err(err)) => {
                tracing::warn!(
                    app = %app_name,
                    host = %raw_host,
                    port = target_port,
                    error = %err,
                    "subdomain reverse proxy websocket handshake error"
                );
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": "bad_gateway",
                        "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                    })),
                )
                    .into_response();
            }
            Err(_) => {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(serde_json::json!({
                        "error": "gateway_timeout",
                        "message": format!("Upstream service {} on port {} handshake timed out.", app_name, target_port),
                    })),
                )
                    .into_response();
            }
        };

        tokio::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                tracing::debug!(error = %err, "upstream websocket connection ended");
            }
        });

        let mut req_builder = hyper::Request::builder()
            .method(req.method().clone())
            .uri(&path_and_query);

        if let Some(hdrs) = req_builder.headers_mut() {
            for (k, v) in incoming_headers.iter() {
                let name_str = k.as_str();
                if is_hop_by_hop_header(name_str)
                    || is_forwarded_header_name(name_str)
                    || is_spoofable_identity_header(name_str)
                    || name_str.eq_ignore_ascii_case("host")
                {
                    continue;
                }
                hdrs.append(k.clone(), v.clone());
            }
            if !raw_host.is_empty() {
                if let Ok(hv) = HeaderValue::from_str(&raw_host) {
                    hdrs.insert(header::HOST, hv);
                }
            }
            for (hn, hv) in canonical_forwarded_headers(
                &incoming_headers,
                &raw_host,
                peer_ip_opt,
                trust_forwarded,
            ) {
                hdrs.insert(hn, hv);
            }
            if let Ok(up_hv) = HeaderValue::from_str(&upgrade_header) {
                hdrs.insert(header::UPGRADE, up_hv);
            }
            hdrs.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));

            for ws_hdr in [
                "sec-websocket-key",
                "sec-websocket-version",
                "sec-websocket-protocol",
                "sec-websocket-extensions",
            ] {
                if let Some(val) = incoming_headers.get(ws_hdr) {
                    if let Ok(hn) = HeaderName::from_bytes(ws_hdr.as_bytes()) {
                        hdrs.insert(hn, val.clone());
                    }
                }
            }

            hdrs.remove("x-aetherflow-user");
            hdrs.remove("x-aetherflow-rutorrent-token");
            if let Some(ref user) = authenticated_user {
                if let Ok(user_hv) = HeaderValue::from_str(user) {
                    hdrs.insert(HeaderName::from_static("x-aetherflow-user"), user_hv);
                }
            }
            if let Some(ref token) = rutorrent_proxy_token {
                if let Ok(token_hv) = HeaderValue::from_str(token) {
                    hdrs.insert(
                        HeaderName::from_static("x-aetherflow-rutorrent-token"),
                        token_hv,
                    );
                }
            }
        }

        let Ok(upstream_ws_req) =
            req_builder.body(http_body_util::Empty::<axum::body::Bytes>::new())
        else {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "bad_gateway",
                    "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                })),
            )
                .into_response();
        };

        let mut upstream_resp = match tokio::time::timeout(
            Duration::from_secs(15),
            sender.send_request(upstream_ws_req),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(err)) => {
                tracing::warn!(
                    app = %app_name,
                    host = %raw_host,
                    port = target_port,
                    error = %err,
                    "subdomain reverse proxy websocket upstream response error"
                );
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": "bad_gateway",
                        "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                    })),
                )
                    .into_response();
            }
            Err(_) => {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(serde_json::json!({
                        "error": "gateway_timeout",
                        "message": format!("Upstream service {} on port {} upgrade timed out.", app_name, target_port),
                    })),
                )
                    .into_response();
            }
        };

        if upstream_resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let resp_headers_clone = upstream_resp.headers().clone();
            let client_upgrade = hyper::upgrade::on(req);
            let upstream_upgrade = hyper::upgrade::on(&mut upstream_resp);

            tokio::spawn(async move {
                match tokio::try_join!(client_upgrade, upstream_upgrade) {
                    Ok((client_upgraded, upstream_upgraded)) => {
                        let mut client_io = hyper_util::rt::TokioIo::new(client_upgraded);
                        let mut upstream_io = hyper_util::rt::TokioIo::new(upstream_upgraded);
                        let _ =
                            tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await;
                    }
                    Err(err) => {
                        tracing::debug!(error = %err, "subdomain websocket upgrade tunnel closed");
                    }
                }
            });

            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            let out_headers = response.headers_mut();
            for (k, v) in resp_headers_clone.iter() {
                out_headers.append(k.clone(), v.clone());
            }
            if !out_headers.contains_key(header::UPGRADE) {
                if let Ok(up_hv) = HeaderValue::from_str(&upgrade_header) {
                    out_headers.insert(header::UPGRADE, up_hv);
                }
            }
            if !out_headers.contains_key(header::CONNECTION) {
                out_headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
            }
            return response;
        } else {
            let (upstream, body) = upstream_resp.into_parts();
            let mut response = Response::new(Body::new(body));
            *response.status_mut() = upstream.status;
            let out_headers = response.headers_mut();
            for (k, v) in &upstream.headers {
                if !is_hop_by_hop_header(k.as_str()) {
                    out_headers.append(k.clone(), v.clone());
                }
            }
            return response;
        }
    }

    let client = if use_tls {
        if !is_strict_loopback_https_url(&target_url) {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "bad_gateway",
                    "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                })),
            )
                .into_response();
        }
        pinned_client.as_ref().unwrap_or(&PROXY_LOOPBACK_TLS_CLIENT)
    } else {
        &*PROXY_HTTP_CLIENT
    };

    let has_body = !hyper::body::Body::is_end_stream(req.body())
        || incoming_headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .is_some_and(|len| len > 0)
        || incoming_headers.contains_key(header::TRANSFER_ENCODING);

    let reqwest_method =
        reqwest::Method::from_bytes(method_str.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut upstream_req = client.request(reqwest_method, &target_url);

    upstream_req = forward_proxy_http_headers(
        upstream_req,
        &incoming_headers,
        &raw_host,
        peer_ip_opt,
        trust_forwarded,
    );
    if let Some(user) = authenticated_user {
        upstream_req = upstream_req.header("X-Aetherflow-User", user);
    }
    if let Some(token) = rutorrent_proxy_token {
        upstream_req = upstream_req.header("X-Aetherflow-Rutorrent-Token", token);
    }

    if has_body {
        upstream_req = upstream_req.body(reqwest::Body::wrap_stream(
            req.into_body().into_data_stream(),
        ));
    }

    let send_res = if has_body {
        Ok(upstream_req.send().await)
    } else {
        tokio::time::timeout(Duration::from_secs(30), upstream_req.send()).await
    };

    match send_res {
        Ok(Ok(upstream_resp)) => {
            let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let upstream_headers = upstream_resp.headers().clone();
            let stream = upstream_resp.bytes_stream();
            let mut response = Response::new(Body::from_stream(stream));
            *response.status_mut() = status;

            let resp_headers = response.headers_mut();
            for (k, v) in upstream_headers.iter() {
                if is_hop_by_hop_header(k.as_str()) {
                    continue;
                }
                if let (Ok(hk), Ok(hv)) = (
                    HeaderName::from_bytes(k.as_str().as_bytes()),
                    HeaderValue::from_bytes(v.as_bytes()),
                ) {
                    resp_headers.append(hk, hv);
                }
            }
            response
        }
        Ok(Err(err)) => {
            tracing::warn!(
                app = %app_name,
                host = %raw_host,
                port = target_port,
                error = %err,
                "subdomain reverse proxy upstream error"
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "bad_gateway",
                    "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                })),
            )
                .into_response()
        }
        Err(_) => {
            tracing::warn!(
                app = %app_name,
                host = %raw_host,
                port = target_port,
                "subdomain reverse proxy upstream timeout"
            );
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({
                    "error": "gateway_timeout",
                    "message": format!("Upstream service {} on port {} timed out.", app_name, target_port),
                })),
            )
                .into_response()
        }
    }
}
