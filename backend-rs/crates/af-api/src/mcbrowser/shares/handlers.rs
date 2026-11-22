use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// Axum HTTP Route Handlers
// ─────────────────────────────────────────────────────────────────────────────

pub(super) async fn list_shares(
    State(runtime): State<ShareRuntime>,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    let res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, _base_root, _policy| list_shares_at(conn, &auth_user))
    })
    .await;

    match res {
        Ok(Ok(shares)) => {
            let mut resp = Json(ListSharesResponse { shares }).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("List shares task failed".to_string()).into_response(),
    }
}

pub(super) async fn create_share(
    State(runtime): State<ShareRuntime>,
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<CreateShareRequest>,
) -> Response {
    let res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, base_root, policy| {
            create_share_at(conn, base_root, policy, &auth_user, req)
        })
    })
    .await;

    match res {
        Ok(Ok((share, _raw_token))) => {
            let mut resp =
                (StatusCode::CREATED, Json(CreateShareResponse { share })).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Create share task failed".to_string()).into_response(),
    }
}

pub(super) async fn delete_share(
    State(runtime): State<ShareRuntime>,
    Extension(auth_user): Extension<AuthUser>,
    AxumPath(share_id): AxumPath<String>,
) -> Response {
    let res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, _base_root, _policy| {
            delete_share_at(conn, &auth_user, &share_id)
        })
    })
    .await;

    match res {
        Ok(Ok(())) => Json(MutationSuccessResponse { success: true }).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Delete share task failed".to_string()).into_response(),
    }
}

pub(super) async fn get_public_share_metadata(
    State(runtime): State<ShareRuntime>,
    AxumPath(token): AxumPath<String>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    if let Err(e) = reject_secret_query_params(raw_query.as_deref()) {
        return public_share_error_response(e);
    }

    let res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, base_root, policy| {
            get_public_metadata_at(conn, base_root, policy, &token)
        })
    })
    .await;

    match res {
        Ok(Ok(meta)) => {
            let mut resp = Json(meta).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(e)) => public_share_error_response(e),
        Err(_) => public_share_error_response(McBrowserError::Internal(
            "Public share metadata task failed".to_string(),
        )),
    }
}

pub(super) async fn unlock_public_share(
    State(runtime): State<ShareRuntime>,
    AxumPath(token): AxumPath<String>,
    RawQuery(raw_query): RawQuery,
    crate::ws::PeerIp(peer_ip): crate::ws::PeerIp,
    headers: HeaderMap,
    Json(req): Json<UnlockShareRequest>,
) -> Response {
    if let Err(e) = reject_secret_query_params(raw_query.as_deref()) {
        return public_share_error_response(e);
    }

    let client_ip = crate::ws::extract_client_ip_for_peer(&headers, peer_ip);
    let res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, base_root, policy| {
            Ok(unlock_public_share_at(
                conn,
                base_root,
                policy,
                &token,
                &req.password,
                &client_ip,
            ))
        })
    })
    .await;

    match res {
        Ok(Ok(Ok((share, access_token, ttl_secs)))) => {
            let cookie = build_scoped_share_cookie(&share.token_hash, &access_token, ttl_secs);
            let mut resp = Json(UnlockShareResponse {
                success: true,
                access_token,
                expires_in: ttl_secs,
            })
            .into_response();
            let h = resp.headers_mut();
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            if let Ok(hv) = HeaderValue::from_str(&cookie) {
                h.insert(header::SET_COOKIE, hv);
            }
            resp
        }
        Ok(Ok(Err(err_resp))) => err_resp,
        Ok(Err(e)) => public_share_error_response(e),
        Err(_) => public_share_error_response(McBrowserError::Internal(
            "Public share unlock task failed".to_string(),
        )),
    }
}

pub(super) async fn list_public_share_entries(
    State(runtime): State<ShareRuntime>,
    AxumPath(token): AxumPath<String>,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<PublicPathQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = reject_secret_query_params(raw_query.as_deref()) {
        return public_share_error_response(e);
    }

    let res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, base_root, policy| {
            list_public_entries_at(conn, base_root, policy, &token, &query.path, &headers)
        })
    })
    .await;

    match res {
        Ok(Ok(entries_resp)) => {
            let mut resp = Json(entries_resp).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(e)) => public_share_error_response(e),
        Err(_) => public_share_error_response(McBrowserError::Internal(
            "Public share entries task failed".to_string(),
        )),
    }
}

pub(super) async fn download_public_share_entry(
    State(runtime): State<ShareRuntime>,
    AxumPath(token): AxumPath<String>,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<PublicPathQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = reject_secret_query_params(raw_query.as_deref()) {
        return public_share_error_response(e);
    }

    let open_res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, base_root, policy| {
            open_public_download_at(conn, base_root, policy, &token, &query.path, &headers)
        })
    })
    .await;

    let (std_file, download_name, total_size, parsed_range) = match open_res {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => return public_share_error_response(e),
        Err(_) => {
            return public_share_error_response(McBrowserError::Internal(
                "Public share download task failed".to_string(),
            ))
        }
    };

    let (status, content_len, content_range_hdr) = match parsed_range {
        ParsedByteRange::Full => (StatusCode::OK, total_size, None),
        ParsedByteRange::Partial { start, end } => {
            let len = end - start + 1;
            let cr = HeaderValue::from_str(&format!("bytes {start}-{end}/{total_size}")).ok();
            (StatusCode::PARTIAL_CONTENT, len, cr)
        }
    };

    let stream = FileRangeStream::new(tokio::fs::File::from_std(std_file), content_len);
    let mut resp = Response::new(Body::from_stream(stream));
    *resp.status_mut() = status;

    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        build_attachment_content_disposition(&download_name),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Ok(len_hv) = HeaderValue::from_str(&content_len.to_string()) {
        h.insert(header::CONTENT_LENGTH, len_hv);
    }
    if let Some(cr) = content_range_hdr {
        h.insert(header::CONTENT_RANGE, cr);
    }
    resp
}
