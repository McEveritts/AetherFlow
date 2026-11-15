use crate::auth::api_error;
use crate::routes::OPENAPI_YAML;
use axum::extract::Path;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

pub async fn swagger_redirect() -> Response {
    let mut resp = StatusCode::TEMPORARY_REDIRECT.into_response();
    let headers = resp.headers_mut();
    headers.insert(
        header::LOCATION,
        HeaderValue::from_static("./swagger/index.html"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

pub async fn swagger_index() -> Response {
    let mut resp = OPENAPI_VIEWER_HTML.into_response();
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    resp
}

pub async fn swagger_asset(Path(any): Path<String>) -> Response {
    let clean = any.trim_start_matches('/');
    match clean {
        "" | "index.html" => swagger_index().await,
        "openapi.yaml" | "doc.yaml" => {
            let mut resp = OPENAPI_YAML.into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/yaml; charset=utf-8"),
            );
            resp
        }
        _ => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "OpenAPI documentation asset not found",
        ),
    }
}

const OPENAPI_VIEWER_HTML: &str = r####"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AetherFlow API — OpenAPI 3.1 Documentation</title>
<style>
  :root {
    --bg-base: #07090e;
    --bg-primary: #0a0d16;
    --bg-secondary: #0f1422;
    --bg-card: #131a29;
    --bg-elevated: #172033;
    --border-subtle: rgba(255, 255, 255, 0.08);
    --border-accent: rgba(129, 140, 248, 0.34);
    --text-primary: #f1f5f9;
    --text-secondary: #cbd5e1;
    --text-muted: #94a3b8;
    --text-dim: #64748b;
    --indigo: #6366f1;
    --indigo-soft: rgba(99, 102, 241, 0.16);
    --indigo-text: #a5b4fc;
    --sky: #38bdf8;
    --sky-soft: rgba(56, 189, 248, 0.14);
    --emerald: #34d399;
    --emerald-soft: rgba(16, 185, 129, 0.14);
    --amber: #fbbf24;
    --amber-soft: rgba(245, 158, 11, 0.14);
    --rose: #f43f5e;
    --rose-soft: rgba(244, 63, 94, 0.14);
    --fuchsia: #e879f9;
    --fuchsia-soft: rgba(217, 70, 239, 0.14);
    --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }

  * { box-sizing: border-box; }
  html, body {
    margin: 0;
    padding: 0;
    background: radial-gradient(circle at 18% 0%, rgba(99, 102, 241, 0.12), transparent 42%),
                radial-gradient(circle at 85% 8%, rgba(56, 189, 248, 0.08), transparent 36%),
                var(--bg-base);
    color: var(--text-primary);
    font-family: var(--font-sans);
    font-size: 14px;
    line-height: 1.5;
    min-height: 100vh;
  }

  a { color: var(--indigo-text); text-decoration: none; }
  a:hover { text-decoration: underline; }
  code, pre, .mono { font-family: var(--font-mono); }

  .topbar {
    position: sticky;
    top: 0;
    z-index: 40;
    backdrop-filter: blur(14px);
    background: rgba(7, 9, 14, 0.88);
    border-bottom: 1px solid var(--border-subtle);
  }
  .topbar-inner {
    max-width: 1360px;
    margin: 0 auto;
    padding: 14px 20px;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .brand-mark {
    width: 34px;
    height: 34px;
    border-radius: 10px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, rgba(99, 102, 241, 0.28), rgba(56, 189, 248, 0.22));
    border: 1px solid var(--border-accent);
    box-shadow: 0 0 22px rgba(99, 102, 241, 0.25);
  }
  .brand-title {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .brand-title h1 {
    margin: 0;
    font-size: 17px;
    font-weight: 700;
    letter-spacing: -0.01em;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 9px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    border: 1px solid var(--border-subtle);
    background: var(--bg-secondary);
    color: var(--text-secondary);
  }
  .pill-indigo {
    background: var(--indigo-soft);
    border-color: var(--border-accent);
    color: var(--indigo-text);
  }
  .pill-emerald {
    background: var(--emerald-soft);
    border-color: rgba(52, 211, 153, 0.35);
    color: var(--emerald);
  }
  .pill-amber {
    background: var(--amber-soft);
    border-color: rgba(251, 191, 36, 0.35);
    color: var(--amber);
  }
  .pill-sky {
    background: var(--sky-soft);
    border-color: rgba(56, 189, 248, 0.35);
    color: var(--sky);
  }
  .pill-rose {
    background: var(--rose-soft);
    border-color: rgba(244, 63, 94, 0.35);
    color: var(--rose);
  }

  .actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .btn, select.select-input {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 7px 12px;
    border-radius: 8px;
    font-size: 12px;
    font-weight: 600;
    border: 1px solid var(--border-subtle);
    background: var(--bg-card);
    color: var(--text-primary);
    cursor: pointer;
    transition: border-color 0.15s ease, background 0.15s ease;
  }
  .btn:hover, select.select-input:hover {
    border-color: var(--border-accent);
    background: var(--bg-elevated);
    text-decoration: none;
  }
  .btn-primary {
    background: rgba(79, 70, 229, 0.28);
    border-color: var(--border-accent);
    color: #e0e7ff;
  }
  .btn-primary:hover {
    background: rgba(79, 70, 229, 0.45);
  }

  .shell {
    max-width: 1360px;
    margin: 0 auto;
    padding: 20px;
    display: grid;
    grid-template-columns: 240px minmax(0, 1fr);
    gap: 20px;
    align-items: start;
  }

  .sidebar {
    position: sticky;
    top: 84px;
    background: rgba(15, 20, 34, 0.8);
    border: 1px solid var(--border-subtle);
    border-radius: 14px;
    padding: 14px;
    max-height: calc(100vh - 104px);
    overflow-y: auto;
  }
  .sidebar-heading {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-dim);
    font-weight: 700;
    margin: 0 0 10px 4px;
  }
  .nav-list {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .nav-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    width: 100%;
    text-align: left;
    padding: 7px 10px;
    border-radius: 8px;
    border: 1px solid transparent;
    background: transparent;
    color: var(--text-secondary);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
  }
  .nav-item:hover {
    background: rgba(255, 255, 255, 0.04);
    color: var(--text-primary);
  }
  .nav-item.active {
    background: var(--indigo-soft);
    border-color: var(--border-accent);
    color: var(--indigo-text);
    font-weight: 600;
  }
  .nav-count {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-dim);
    background: rgba(255, 255, 255, 0.04);
    padding: 1px 6px;
    border-radius: 999px;
  }

  .main {
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .card {
    background: rgba(15, 20, 34, 0.78);
    border: 1px solid var(--border-subtle);
    border-radius: 14px;
    padding: 16px 18px;
  }
  .info-banner {
    border-color: rgba(245, 158, 11, 0.25);
    background: linear-gradient(135deg, rgba(245, 158, 11, 0.08), rgba(15, 20, 34, 0.85));
  }
  .info-banner p {
    margin: 0;
    color: var(--text-secondary);
    font-size: 13px;
  }
  .info-banner code {
    background: rgba(0, 0, 0, 0.35);
    padding: 1px 5px;
    border-radius: 5px;
    color: var(--sky);
    font-size: 12px;
  }

  .toolbar {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    justify-content: space-between;
  }
  .search-wrap {
    flex: 1 1 280px;
    position: relative;
  }
  .search-input {
    width: 100%;
    padding: 9px 12px;
    border-radius: 10px;
    border: 1px solid var(--border-subtle);
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 13px;
    outline: none;
  }
  .search-input:focus {
    border-color: var(--indigo);
    box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.16);
  }
  .filter-group {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: center;
  }
  .chip {
    padding: 5px 10px;
    border-radius: 8px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.03em;
    border: 1px solid var(--border-subtle);
    background: var(--bg-primary);
    color: var(--text-muted);
    cursor: pointer;
  }
  .chip:hover { color: var(--text-primary); border-color: rgba(255, 255, 255, 0.18); }
  .chip.active {
    background: var(--indigo-soft);
    border-color: var(--border-accent);
    color: var(--indigo-text);
  }

  .stats-row {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    font-size: 12px;
    color: var(--text-muted);
  }

  .tag-section {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .tag-header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    padding: 4px 4px 6px 4px;
    border-bottom: 1px solid var(--border-subtle);
  }
  .tag-header h2 {
    margin: 0;
    font-size: 16px;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .tag-desc {
    font-size: 12px;
    color: var(--text-muted);
  }

  .op-card {
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    background: rgba(19, 26, 41, 0.72);
    overflow: hidden;
    transition: border-color 0.15s ease;
  }
  .op-card:hover { border-color: rgba(255, 255, 255, 0.16); }
  .op-card.open { border-color: var(--border-accent); }

  .op-summary {
    width: 100%;
    text-align: left;
    border: none;
    background: transparent;
    color: inherit;
    padding: 11px 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    cursor: pointer;
  }
  .op-left {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
    flex-wrap: wrap;
  }
  .op-right {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }

  .method {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 64px;
    padding: 3px 8px;
    border-radius: 7px;
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    border: 1px solid transparent;
  }
  .m-get { background: var(--sky-soft); color: var(--sky); border-color: rgba(56, 189, 248, 0.32); }
  .m-post { background: var(--emerald-soft); color: var(--emerald); border-color: rgba(52, 211, 153, 0.32); }
  .m-put { background: var(--amber-soft); color: var(--amber); border-color: rgba(251, 191, 36, 0.32); }
  .m-delete { background: var(--rose-soft); color: var(--rose); border-color: rgba(244, 63, 94, 0.32); }
  .m-patch { background: var(--fuchsia-soft); color: var(--fuchsia); border-color: rgba(232, 121, 249, 0.32); }
  .m-head { background: var(--indigo-soft); color: var(--indigo-text); border-color: var(--border-accent); }

  .op-path {
    font-family: var(--font-mono);
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
    word-break: break-all;
  }
  .path-param {
    color: var(--indigo-text);
    background: var(--indigo-soft);
    padding: 1px 4px;
    border-radius: 4px;
  }
  .op-desc-inline {
    font-size: 13px;
    color: var(--text-muted);
  }
  .lock-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 999px;
  }
  .lock-protected {
    background: var(--amber-soft);
    color: var(--amber);
    border: 1px solid rgba(251, 191, 36, 0.28);
  }
  .lock-public {
    background: rgba(255, 255, 255, 0.05);
    color: var(--text-muted);
    border: 1px solid var(--border-subtle);
  }

  .op-details {
    border-top: 1px solid var(--border-subtle);
    padding: 14px 16px 16px 16px;
    background: rgba(10, 13, 22, 0.72);
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .section-label {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    color: var(--text-dim);
    margin: 0 0 6px 0;
  }
  .op-full-desc {
    margin: 0;
    color: var(--text-secondary);
    font-size: 13px;
    white-space: pre-wrap;
  }

  table.spec-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    background: rgba(7, 9, 14, 0.55);
    border: 1px solid var(--border-subtle);
    border-radius: 10px;
    overflow: hidden;
  }
  table.spec-table th, table.spec-table td {
    text-align: left;
    padding: 8px 10px;
    border-bottom: 1px solid var(--border-subtle);
    vertical-align: top;
  }
  table.spec-table th {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-dim);
    background: rgba(255, 255, 255, 0.02);
  }
  table.spec-table tr:last-child td { border-bottom: none; }

  .req-star {
    color: var(--rose);
    font-weight: 700;
    margin-left: 4px;
  }
  .code-block {
    margin: 0;
    padding: 10px 12px;
    border-radius: 10px;
    background: #05070c;
    border: 1px solid var(--border-subtle);
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-secondary);
    overflow-x: auto;
    max-height: 360px;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .try-box {
    border: 1px solid var(--border-accent);
    background: rgba(99, 102, 241, 0.06);
    border-radius: 10px;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .try-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 8px;
  }
  .field-group {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .field-label {
    font-size: 11px;
    color: var(--text-muted);
    font-family: var(--font-mono);
  }
  .field-input, .field-textarea {
    width: 100%;
    padding: 7px 9px;
    border-radius: 8px;
    border: 1px solid var(--border-subtle);
    background: var(--bg-base);
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 12px;
    outline: none;
  }
  .field-textarea { min-height: 84px; resize: vertical; }
  .field-input:focus, .field-textarea:focus { border-color: var(--indigo); }

  .schema-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
    gap: 10px;
  }
  .schema-card {
    background: rgba(19, 26, 41, 0.65);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    padding: 12px 14px;
  }
  .schema-card summary {
    cursor: pointer;
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 13px;
    color: var(--indigo-text);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .modal-backdrop {
    position: fixed;
    inset: 0;
    z-index: 60;
    background: rgba(3, 5, 10, 0.8);
    backdrop-filter: blur(6px);
    display: none;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }
  .modal-backdrop.open { display: flex; }
  .modal {
    width: min(980px, 100%);
    max-height: 86vh;
    background: var(--bg-primary);
    border: 1px solid var(--border-accent);
    border-radius: 14px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border-subtle);
  }
  .modal-body {
    padding: 14px 16px;
    overflow: auto;
  }

  .hidden { display: none !important; }
  .muted { color: var(--text-muted); }

  @media (max-width: 960px) {
    .shell { grid-template-columns: 1fr; }
    .sidebar { position: static; max-height: none; }
    .nav-list { flex-direction: row; flex-wrap: wrap; }
    .nav-item { width: auto; }
  }
</style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
            <path d="M12 3L4 7.5V16.5L12 21L20 16.5V7.5L12 3Z" stroke="#a5b4fc" stroke-width="1.8" stroke-linejoin="round"/>
            <path d="M12 8V16M8 10L12 12.5L16 10" stroke="#38bdf8" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </span>
        <div>
          <div class="brand-title">
            <h1 id="api-title">AetherFlow API</h1>
            <span class="pill pill-indigo" id="spec-version">OpenAPI 3.1.0</span>
            <span class="pill" id="api-version">v3.1.0</span>
            <span class="pill pill-emerald" id="security-pill">cookieAuth</span>
          </div>
          <div class="muted" style="font-size:12px;">Zero-CDN offline OpenAPI explorer</div>
        </div>
      </div>
      <div class="actions">
        <label class="muted" for="server-select" style="font-size:12px;">Server:</label>
        <select id="server-select" class="select-input" aria-label="Target server base path">
          <option value="/api/v1">/api/v1 (Canonical v1)</option>
        </select>
        <button type="button" class="btn" id="btn-expand-all">Expand All</button>
        <button type="button" class="btn" id="btn-collapse-all">Collapse All</button>
        <button type="button" class="btn" id="btn-raw-yaml">Raw YAML</button>
        <a class="btn btn-primary" id="download-spec-link" href="../openapi.yaml" download="openapi-v1.yaml">Download openapi.yaml</a>
      </div>
    </div>
  </header>

  <main class="shell">
    <aside class="sidebar">
      <div class="sidebar-heading">Endpoint Tags</div>
      <div class="nav-list" id="tag-nav"></div>
    </aside>

    <section class="main">
      <noscript>
        <div class="card info-banner">
          <p>JavaScript is disabled. You can still download the raw OpenAPI 3.1 specification at <a href="../openapi.yaml">openapi.yaml</a>.</p>
        </div>
      </noscript>

      <div id="info-banner" class="card info-banner hidden">
        <p id="info-desc"></p>
      </div>

      <div class="card">
        <div class="toolbar">
          <div class="search-wrap">
            <input id="search-input" class="search-input" type="search" placeholder="Filter endpoints by path, tag, summary, parameter, or schema..." aria-label="Filter endpoints" />
          </div>
          <div class="filter-group" id="method-filters" role="group" aria-label="Filter by HTTP method">
            <button type="button" class="chip active" data-method="ALL">ALL</button>
            <button type="button" class="chip" data-method="GET">GET</button>
            <button type="button" class="chip" data-method="POST">POST</button>
            <button type="button" class="chip" data-method="PUT">PUT</button>
            <button type="button" class="chip" data-method="PATCH">PATCH</button>
            <button type="button" class="chip" data-method="DELETE">DELETE</button>
            <button type="button" class="chip" data-method="HEAD">HEAD</button>
          </div>
          <div class="filter-group" id="auth-filters" role="group" aria-label="Filter by authentication">
            <button type="button" class="chip active" data-auth="ALL">Any Auth</button>
            <button type="button" class="chip" data-auth="PROTECTED">Protected</button>
            <button type="button" class="chip" data-auth="PUBLIC">Public</button>
          </div>
        </div>
        <div class="stats-row" id="stats-row" style="margin-top:10px;">Loading OpenAPI specification...</div>
      </div>

      <div id="error-box" class="card hidden" style="border-color: rgba(244, 63, 94, 0.45);">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
          <div>
            <strong style="color:var(--rose);">Failed to load OpenAPI specification</strong>
            <div class="muted" id="error-msg" style="font-size:12px;margin-top:4px;"></div>
          </div>
          <button type="button" class="btn" id="btn-retry">Retry</button>
        </div>
      </div>

      <div id="endpoints-root"></div>

      <section class="card" id="schemas-section">
        <div class="tag-header" style="margin-bottom:12px;">
          <h2>Component Schemas &amp; Definitions</h2>
          <span class="tag-desc" id="schemas-count"></span>
        </div>
        <div class="schema-grid" id="schemas-root"></div>
      </section>
    </section>
  </main>

  <div class="modal-backdrop" id="raw-modal" role="dialog" aria-modal="true" aria-labelledby="raw-modal-title">
    <div class="modal">
      <div class="modal-header">
        <strong id="raw-modal-title">openapi-v1.yaml</strong>
        <div class="actions">
          <button type="button" class="btn" id="btn-copy-yaml">Copy YAML</button>
          <button type="button" class="btn" id="btn-close-modal">Close</button>
        </div>
      </div>
      <div class="modal-body">
        <pre class="code-block" id="raw-yaml-pre" style="max-height:70vh;"></pre>
      </div>
    </div>
  </div>

<script>
(() => {
  'use strict';

  function parseYaml(text) {
    const src = String(text || '').replace(/\r\n?/g, '\n');
    const lines = src.split('\n');

    function stripComment(line) {
      let inSingle = false;
      let inDouble = false;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === "'" && !inDouble) {
          if (inSingle && line[i + 1] === "'") { i++; continue; }
          inSingle = !inSingle;
        } else if (ch === '"' && !inSingle) {
          if (inDouble && line[i - 1] === '\\') {
            let bs = 0;
            for (let j = i - 1; j >= 0 && line[j] === '\\'; j--) bs++;
            if (bs % 2 === 1) continue;
          }
          inDouble = !inDouble;
        } else if (ch === '#' && !inSingle && !inDouble) {
          if (i === 0 || /\s/.test(line[i - 1])) {
            return line.slice(0, i);
          }
        }
      }
      return line;
    }

    function unescapeDouble(raw) {
      return raw.replace(/\\(["\\/bfnrt]|u[0-9a-fA-F]{4})/g, (_, esc) => {
        switch (esc[0]) {
          case '"': return '"';
          case '\\': return '\\';
          case '/': return '/';
          case 'b': return '\b';
          case 'f': return '\f';
          case 'n': return '\n';
          case 'r': return '\r';
          case 't': return '\t';
          case 'u': return String.fromCharCode(parseInt(esc.slice(1), 16));
          default: return esc;
        }
      });
    }

    function parseScalar(raw) {
      const t = raw.trim();
      if (t === '' || t === 'null' || t === '~') return null;
      if (t === 'true') return true;
      if (t === 'false') return false;
      if (/^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?$/.test(t)) {
        const n = Number(t);
        if (Number.isFinite(n)) return n;
      }
      if (t.startsWith("'") && t.endsWith("'") && t.length >= 2) {
        return t.slice(1, -1).replace(/''/g, "'");
      }
      if (t.startsWith('"') && t.endsWith('"') && t.length >= 2) {
        return unescapeDouble(t.slice(1, -1));
      }
      return t;
    }

    function parseFlow(str, startPos) {
      let i = startPos || 0;
      const len = str.length;

      function skipWs() {
        while (i < len) {
          const ch = str[i];
          if (ch === ' ' || ch === '\t' || ch === '\n') {
            i++;
          } else if (ch === '#' && (i === 0 || /\s/.test(str[i - 1]))) {
            while (i < len && str[i] !== '\n') i++;
          } else {
            break;
          }
        }
      }

      function readQuoted(quote) {
        i++;
        let out = '';
        while (i < len) {
          const ch = str[i];
          if (quote === "'") {
            if (ch === "'" && str[i + 1] === "'") {
              out += "'";
              i += 2;
              continue;
            }
            if (ch === "'") {
              i++;
              return out;
            }
            out += ch;
            i++;
          } else {
            if (ch === '\\' && i + 1 < len) {
              out += ch + str[i + 1];
              i += 2;
              continue;
            }
            if (ch === '"') {
              i++;
              return unescapeDouble(out);
            }
            out += ch;
            i++;
          }
        }
        return quote === '"' ? unescapeDouble(out) : out;
      }

      function parseValue() {
        skipWs();
        if (i >= len) return null;
        const ch = str[i];
        if (ch === '{') return parseObject();
        if (ch === '[') return parseArray();
        if (ch === "'") return readQuoted("'");
        if (ch === '"') return readQuoted('"');
        const start = i;
        while (i < len) {
          const c = str[i];
          if (c === ',' || c === '}' || c === ']' || c === '\n') break;
          if (c === '#' && i > start && /\s/.test(str[i - 1])) break;
          i++;
        }
        return parseScalar(str.slice(start, i));
      }

      function parseKey() {
        skipWs();
        if (i >= len) return '';
        if (str[i] === "'") return readQuoted("'");
        if (str[i] === '"') return readQuoted('"');
        const start = i;
        while (i < len) {
          const c = str[i];
          if (c === ':' && (i + 1 >= len || /\s|[},\]\n]/.test(str[i + 1]) || str[i + 1] === ':')) {
            break;
          }
          if (c === ',' || c === '}' || c === ']') break;
          i++;
        }
        return str.slice(start, i).trim();
      }

      function parseObject() {
        const obj = {};
        i++;
        while (i < len) {
          skipWs();
          if (i >= len) break;
          if (str[i] === '}') { i++; break; }
          if (str[i] === ',') { i++; continue; }
          const key = String(parseKey());
          skipWs();
          if (str[i] === ':') {
            i++;
            obj[key] = parseValue();
          } else {
            obj[key] = null;
          }
        }
        return obj;
      }

      function parseArray() {
        const arr = [];
        i++;
        while (i < len) {
          skipWs();
          if (i >= len) break;
          if (str[i] === ']') { i++; break; }
          if (str[i] === ',') { i++; continue; }
          arr.push(parseValue());
        }
        return arr;
      }

      return { value: parseValue(), nextPos: i };
    }

    function findColonIndex(trimmed) {
      let inSingle = false;
      let inDouble = false;
      for (let i = 0; i < trimmed.length; i++) {
        const ch = trimmed[i];
        if (ch === "'" && !inDouble) {
          if (inSingle && trimmed[i + 1] === "'") { i++; continue; }
          inSingle = !inSingle;
        } else if (ch === '"' && !inSingle) {
          if (inDouble && trimmed[i - 1] === '\\') {
            let bs = 0;
            for (let j = i - 1; j >= 0 && trimmed[j] === '\\'; j--) bs++;
            if (bs % 2 === 1) continue;
          }
          inDouble = !inDouble;
        } else if (ch === ':' && !inSingle && !inDouble) {
          if (i + 1 === trimmed.length || /\s/.test(trimmed[i + 1])) {
            return i;
          }
        }
      }
      return -1;
    }

    const lineOffsets = [];
    {
      let off = 0;
      for (let idx = 0; idx < lines.length; idx++) {
        lineOffsets.push(off);
        off += lines[idx].length + 1;
      }
    }

    function nextNonEmptyLine(idx) {
      while (idx < lines.length) {
        const cleaned = stripComment(lines[idx]);
        const t = cleaned.trim();
        if (t !== '' && t !== '---' && t !== '...') {
          return idx;
        }
        idx++;
      }
      return lines.length;
    }

    function lineIndent(line) {
      let n = 0;
      while (n < line.length && line[n] === ' ') n++;
      return n;
    }

    function advanceToLineForOffset(absPos) {
      const target = Math.max(0, absPos - 1);
      let lo = 0;
      let hi = lineOffsets.length - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (lineOffsets[mid] <= target) lo = mid + 1;
        else hi = mid - 1;
      }
      return Math.max(0, hi) + 1;
    }

    function parseBlockScalar(startLineIdx, baseIndent, header) {
      const isFolded = header[0] === '>';
      const chomp = header.includes('-') ? 'strip' : (header.includes('+') ? 'keep' : 'clip');
      let idx = startLineIdx;
      let contentIndent = -1;
      const rawLines = [];
      while (idx < lines.length) {
        const raw = lines[idx];
        if (raw.trim() === '') {
          rawLines.push('');
          idx++;
          continue;
        }
        const ind = lineIndent(raw);
        if (ind <= baseIndent) break;
        if (contentIndent === -1) contentIndent = ind;
        rawLines.push(raw.slice(Math.min(contentIndent, raw.length)));
        idx++;
      }
      while (rawLines.length > 0 && rawLines[rawLines.length - 1] === '') {
        if (chomp === 'keep') break;
        rawLines.pop();
      }
      let out = '';
      if (isFolded) {
        for (let i = 0; i < rawLines.length; i++) {
          const cur = rawLines[i];
          if (i > 0) {
            out += (cur === '' || rawLines[i - 1] === '') ? '\n' : ' ';
          }
          out += cur;
        }
      } else {
        out = rawLines.join('\n');
      }
      if (chomp !== 'strip' && rawLines.length > 0) out += '\n';
      return { value: out, nextLine: idx };
    }

    function parseValueAfterColon(lineIdx, keyIndent, restRaw, colonEndCol) {
      const rest = restRaw.trim();
      if (rest === '') {
        const nxt = nextNonEmptyLine(lineIdx + 1);
        if (nxt >= lines.length) return { value: null, nextLine: nxt };
        const nxtCleaned = stripComment(lines[nxt]);
        const nxtInd = lineIndent(nxtCleaned);
        if (nxtInd > keyIndent || (nxtInd === keyIndent && nxtCleaned.trim().startsWith('-'))) {
          return parseBlock(nxt, nxtInd);
        }
        return { value: null, nextLine: nxt };
      }
      if (/^[>|][+-]?\d*$/.test(rest)) {
        return parseBlockScalar(lineIdx + 1, keyIndent, rest);
      }
      if (rest.startsWith('{') || rest.startsWith('[')) {
        const lineStr = lines[lineIdx];
        const relPos = lineStr.indexOf(rest[0], colonEndCol);
        const absStart = lineOffsets[lineIdx] + Math.max(colonEndCol, relPos);
        const res = parseFlow(src, absStart);
        return { value: res.value, nextLine: advanceToLineForOffset(res.nextPos) };
      }
      return { value: parseScalar(rest), nextLine: lineIdx + 1 };
    }

    function parseBlock(startIdx, expectedIndent) {
      let idx = nextNonEmptyLine(startIdx);
      if (idx >= lines.length) return { value: null, nextLine: idx };
      const firstTrim = stripComment(lines[idx]).trim();
      if (firstTrim === '-' || firstTrim.startsWith('- ')) {
        const arr = [];
        while (idx < lines.length) {
          idx = nextNonEmptyLine(idx);
          if (idx >= lines.length) break;
          const cleaned = stripComment(lines[idx]);
          const ind = lineIndent(cleaned);
          if (ind < expectedIndent) break;
          const trimmed = cleaned.trim();
          if (ind !== expectedIndent || !(trimmed === '-' || trimmed.startsWith('- '))) break;
          const afterDash = trimmed.slice(1).trim();
          if (afterDash === '') {
            const nxt = nextNonEmptyLine(idx + 1);
            if (nxt < lines.length && lineIndent(stripComment(lines[nxt])) > ind) {
              const sub = parseBlock(nxt, lineIndent(stripComment(lines[nxt])));
              arr.push(sub.value);
              idx = sub.nextLine;
            } else {
              arr.push(null);
              idx++;
            }
          } else if (afterDash.startsWith('{') || afterDash.startsWith('[')) {
            const dashCol = cleaned.indexOf('-');
            const flowCharCol = cleaned.indexOf(afterDash[0], dashCol + 1);
            const absStart = lineOffsets[idx] + flowCharCol;
            const res = parseFlow(src, absStart);
            arr.push(res.value);
            idx = advanceToLineForOffset(res.nextPos);
          } else {
            const colon = findColonIndex(afterDash);
            if (colon !== -1) {
              const k = String(parseScalar(afterDash.slice(0, colon)));
              const rest = afterDash.slice(colon + 1);
              const itemIndent = cleaned.indexOf('-') + 2;
              const afterDashCol = cleaned.indexOf(afterDash[0], cleaned.indexOf('-') + 1);
              const firstVal = parseValueAfterColon(idx, itemIndent, rest, afterDashCol + colon + 1);
              const itemObj = { [k]: firstVal.value };
              idx = firstVal.nextLine;
              while (idx < lines.length) {
                idx = nextNonEmptyLine(idx);
                if (idx >= lines.length) break;
                const nc = stripComment(lines[idx]);
                const ni = lineIndent(nc);
                if (ni !== itemIndent) break;
                const nt = nc.trim();
                if (nt === '-' || nt.startsWith('- ')) break;
                const c2 = findColonIndex(nt);
                if (c2 === -1) break;
                const k2 = String(parseScalar(nt.slice(0, c2)));
                const r2 = nt.slice(c2 + 1);
                const v2 = parseValueAfterColon(idx, ni, r2, ni + c2 + 1);
                itemObj[k2] = v2.value;
                idx = v2.nextLine;
              }
              arr.push(itemObj);
            } else {
              arr.push(parseScalar(afterDash));
              idx++;
            }
          }
        }
        return { value: arr, nextLine: idx };
      }

      const obj = {};
      while (idx < lines.length) {
        idx = nextNonEmptyLine(idx);
        if (idx >= lines.length) break;
        const cleaned = stripComment(lines[idx]);
        const ind = lineIndent(cleaned);
        if (ind !== expectedIndent) break;
        const trimmed = cleaned.trim();
        if (trimmed === '-' || trimmed.startsWith('- ')) break;
        const colon = findColonIndex(trimmed);
        if (colon === -1) { idx++; continue; }
        const key = String(parseScalar(trimmed.slice(0, colon)));
        const rest = trimmed.slice(colon + 1);
        const res = parseValueAfterColon(idx, ind, rest, ind + colon + 1);
        obj[key] = res.value;
        idx = res.nextLine;
      }
      return { value: obj, nextLine: idx };
    }

    const first = nextNonEmptyLine(0);
    if (first >= lines.length) return {};
    const firstCleaned = stripComment(lines[first]);
    if (firstCleaned.trim().startsWith('{') || firstCleaned.trim().startsWith('[')) {
      return parseFlow(src, lineOffsets[first] + lineIndent(firstCleaned)).value;
    }
    return parseBlock(first, lineIndent(firstCleaned)).value;
  }

  function el(tag, props, children) {
    const node = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (k === 'className') node.className = v;
        else if (k === 'text') node.textContent = v;
        else if (k.startsWith('on') && typeof v === 'function') {
          node.addEventListener(k.slice(2).toLowerCase(), v);
        } else if (v !== null && v !== undefined) {
          node.setAttribute(k, String(v));
        }
      }
    }
    if (children !== undefined && children !== null) {
      const arr = Array.isArray(children) ? children : [children];
      for (const c of arr) {
        if (c === null || c === undefined) continue;
        node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
      }
    }
    return node;
  }

  function renderRichInline(target, text) {
    target.textContent = '';
    const tokens = String(text || '').split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
    for (const tok of tokens) {
      if (!tok) continue;
      if (tok.startsWith('**') && tok.endsWith('**') && tok.length > 4) {
        target.appendChild(el('strong', { text: tok.slice(2, -2) }));
      } else if (tok.startsWith('`') && tok.endsWith('`') && tok.length > 2) {
        target.appendChild(el('code', { text: tok.slice(1, -1) }));
      } else {
        target.appendChild(document.createTextNode(tok));
      }
    }
  }

  function resolvePointer(doc, ref) {
    if (!ref || typeof ref !== 'string' || !ref.startsWith('#/')) return null;
    const parts = ref.slice(2).split('/').map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~'));
    let cur = doc;
    for (const p of parts) {
      if (cur && typeof cur === 'object' && Object.prototype.hasOwnProperty.call(cur, p)) {
        cur = cur[p];
      } else {
        return null;
      }
    }
    return cur;
  }

  function deref(doc, obj, seen) {
    if (!obj || typeof obj !== 'object') return obj;
    const visited = seen || new Set();
    if (obj.$ref && typeof obj.$ref === 'string') {
      if (visited.has(obj.$ref)) return obj;
      visited.add(obj.$ref);
      const target = resolvePointer(doc, obj.$ref);
      if (target) {
        const resolved = deref(doc, target, visited);
        if (typeof resolved === 'object' && !Array.isArray(resolved)) {
          return Object.assign({}, resolved, { _refName: obj.$ref.split('/').pop() });
        }
        return resolved;
      }
    }
    return obj;
  }

  function describeSchemaType(doc, schema, depth) {
    const d = depth || 0;
    if (!schema || typeof schema !== 'object') return 'any';
    if (schema.$ref) {
      const refName = schema.$ref.split('/').pop();
      return d > 4 ? refName : refName;
    }
    if (schema.type === 'array') {
      const itemType = schema.items ? describeSchemaType(doc, schema.items, d + 1) : 'any';
      return 'array<' + itemType + '>';
    }
    if (schema.type) {
      let label = schema.type;
      if (schema.format) label += ' (' + schema.format + ')';
      if (Array.isArray(schema.enum)) label += ' [' + schema.enum.join(' | ') + ']';
      if (schema.const !== undefined) label += ' = "' + schema.const + '"';
      return label;
    }
    if (schema.additionalProperties) return 'map<string, any>';
    return 'object';
  }

  function schemaConstraints(schema) {
    if (!schema || typeof schema !== 'object') return '';
    const bits = [];
    if (schema.minLength !== undefined) bits.push('minLength: ' + schema.minLength);
    if (schema.maxLength !== undefined) bits.push('maxLength: ' + schema.maxLength);
    if (schema.minimum !== undefined) bits.push('min: ' + schema.minimum);
    if (schema.maximum !== undefined) bits.push('max: ' + schema.maximum);
    if (schema.default !== undefined) bits.push('default: ' + JSON.stringify(schema.default));
    return bits.join(', ');
  }

  function sampleFromSchema(doc, schema, depth, seen) {
    const d = depth || 0;
    if (!schema || typeof schema !== 'object' || d > 4) return {};
    const visited = seen ? new Set(seen) : new Set();
    if (schema.$ref) {
      if (visited.has(schema.$ref)) return {};
      visited.add(schema.$ref);
      const target = resolvePointer(doc, schema.$ref);
      return target ? sampleFromSchema(doc, target, d + 1, visited) : {};
    }
    if (schema.const !== undefined) return schema.const;
    if (Array.isArray(schema.enum) && schema.enum.length > 0) return schema.enum[0];
    if (schema.default !== undefined) return schema.default;
    if (schema.type === 'string') {
      if (schema.format === 'binary') return '<binary>';
      return 'string';
    }
    if (schema.type === 'integer') return schema.minimum !== undefined ? schema.minimum : 0;
    if (schema.type === 'number') return schema.minimum !== undefined ? schema.minimum : 0;
    if (schema.type === 'boolean') return false;
    if (schema.type === 'array') {
      return [sampleFromSchema(doc, schema.items || { type: 'object' }, d + 1, visited)];
    }
    if (schema.type === 'object' || schema.properties || schema.additionalProperties) {
      const out = {};
      if (schema.properties && typeof schema.properties === 'object') {
        for (const [k, prop] of Object.entries(schema.properties)) {
          out[k] = sampleFromSchema(doc, prop, d + 1, visited);
        }
      } else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        out.key = sampleFromSchema(doc, schema.additionalProperties, d + 1, visited);
      }
      return out;
    }
    return {};
  }

  function renderSchemaTable(doc, rawSchema) {
    const schema = deref(doc, rawSchema);
    if (!schema || typeof schema !== 'object') return null;
    if (schema.type === 'array' && schema.items) {
      const itemResolved = deref(doc, schema.items);
      if (itemResolved && itemResolved.properties) {
        return renderSchemaTable(doc, itemResolved);
      }
    }
    if (!schema.properties || typeof schema.properties !== 'object') return null;
    const requiredSet = new Set(Array.isArray(schema.required) ? schema.required : []);
    const rows = Object.entries(schema.properties).map(([name, propRaw]) => {
      const prop = deref(doc, propRaw);
      const isReq = requiredSet.has(name);
      const typeLabel = describeSchemaType(doc, propRaw, 0);
      const extra = schemaConstraints(prop);
      const descText = [prop && prop.description ? prop.description : '', extra].filter(Boolean).join(' — ');
      return el('tr', null, [
        el('td', null, [
          el('code', { text: name }),
          isReq ? el('span', { className: 'req-star', text: '*' }) : null,
        ]),
        el('td', null, el('code', { className: 'muted', text: typeLabel })),
        el('td', { className: 'muted', text: descText || '—' }),
      ]);
    });
    return el('table', { className: 'spec-table' }, [
      el('thead', null, el('tr', null, [
        el('th', { text: 'Field' }),
        el('th', { text: 'Type' }),
        el('th', { text: 'Details' }),
      ])),
      el('tbody', null, rows),
    ]);
  }

  function renderPathSpan(pathStr) {
    const span = el('span', { className: 'op-path' });
    const parts = pathStr.split(/(\{[^}]+\})/g);
    for (const part of parts) {
      if (!part) continue;
      if (part.startsWith('{') && part.endsWith('}')) {
        span.appendChild(el('span', { className: 'path-param', text: part }));
      } else {
        span.appendChild(document.createTextNode(part));
      }
    }
    return span;
  }

  function computeSpecUrl() {
    const p = window.location.pathname || '/api/v1/public/swagger/index.html';
    if (p.includes('/swagger/')) {
      return new URL('../openapi.yaml', window.location.href).pathname;
    }
    if (p.endsWith('/swagger')) {
      return p.slice(0, -'/swagger'.length) + '/openapi.yaml';
    }
    return '../openapi.yaml';
  }

  const state = {
    spec: null,
    rawYaml: '',
    specUrl: computeSpecUrl(),
    selectedTag: 'ALL',
    selectedMethod: 'ALL',
    selectedAuth: 'ALL',
    searchQuery: '',
    expandedKeys: new Set(),
  };

  function collectOperations(spec) {
    const methods = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head'];
    const ops = [];
    const paths = (spec && spec.paths) || {};
    for (const [pathStr, pathItem] of Object.entries(paths)) {
      if (!pathItem || typeof pathItem !== 'object') continue;
      const sharedParams = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];
      for (const method of methods) {
        const op = pathItem[method];
        if (!op || typeof op !== 'object') continue;
        const opParams = Array.isArray(op.parameters) ? op.parameters : [];
        const mergedParams = [];
        const seenParamKeys = new Set();
        for (const p of [...opParams, ...sharedParams]) {
          const resolved = deref(spec, p);
          if (!resolved) continue;
          const pk = (resolved.in || '') + ':' + (resolved.name || '');
          if (!seenParamKeys.has(pk)) {
            seenParamKeys.add(pk);
            mergedParams.push(resolved);
          }
        }
        const tags = Array.isArray(op.tags) && op.tags.length > 0 ? op.tags : ['General'];
        const security = Array.isArray(op.security) ? op.security : (Array.isArray(spec.security) ? spec.security : []);
        const secNames = [];
        for (const req of security) {
          if (req && typeof req === 'object') {
            for (const key of Object.keys(req)) secNames.push(key);
          }
        }
        ops.push({
          key: method.toUpperCase() + ' ' + pathStr,
          method: method.toUpperCase(),
          path: pathStr,
          summary: op.summary || '',
          description: op.description || '',
          tags,
          parameters: mergedParams,
          requestBody: op.requestBody ? deref(spec, op.requestBody) : null,
          responses: op.responses || {},
          securityNames: secNames,
          isProtected: secNames.length > 0,
        });
      }
    }
    return ops;
  }

  function buildTryItOut(spec, op) {
    const box = el('div', { className: 'try-box' });
    const serverSel = document.getElementById('server-select');
    const paramInputs = {};
    const grid = el('div', { className: 'try-grid' });

    for (const param of op.parameters) {
      const schema = deref(spec, param.schema || {});
      const input = el('input', {
        className: 'field-input',
        type: 'text',
        placeholder: schema && schema.default !== undefined ? String(schema.default) : (param.in + ' ' + param.name),
      });
      paramInputs[param.in + ':' + param.name] = { param, input };
      grid.appendChild(el('div', { className: 'field-group' }, [
        el('label', { className: 'field-label', text: param.name + ' (' + param.in + ')' + (param.required ? ' *' : '') }),
        input,
      ]));
    }

    const csrfInput = el('input', { className: 'field-input', type: 'text', placeholder: 'Optional X-CSRF-Token' });
    if (op.method !== 'GET' && op.method !== 'HEAD') {
      grid.appendChild(el('div', { className: 'field-group' }, [
        el('label', { className: 'field-label', text: 'X-CSRF-Token (header)' }),
        csrfInput,
      ]));
    }

    if (grid.children.length > 0) box.appendChild(grid);

    let bodyTextarea = null;
    let contentType = 'application/json';
    if (op.requestBody && op.requestBody.content) {
      const ctypes = Object.keys(op.requestBody.content);
      if (ctypes.length > 0) contentType = ctypes[0];
      const media = op.requestBody.content[contentType] || {};
      const sample = media.schema ? sampleFromSchema(spec, media.schema, 0) : {};
      bodyTextarea = el('textarea', { className: 'field-textarea' });
      if (contentType === 'application/json') {
        bodyTextarea.value = JSON.stringify(sample, null, 2);
      }
      box.appendChild(el('div', { className: 'field-group' }, [
        el('label', { className: 'field-label', text: 'Request Body (' + contentType + ')' }),
        bodyTextarea,
      ]));
    }

    const resultWrap = el('div', { className: 'hidden' });
    const statusLine = el('div', { className: 'stats-row' });
    const resultPre = el('pre', { className: 'code-block' });
    resultWrap.appendChild(statusLine);
    resultWrap.appendChild(resultPre);

    const runBtn = el('button', {
      type: 'button',
      className: 'btn btn-primary',
      text: 'Execute Request',
      onClick: async () => {
        const base = (serverSel && serverSel.value ? serverSel.value : '/api/v1').replace(/\/$/, '');
        let finalPath = op.path;
        const query = new URLSearchParams();
        const headers = {};
        for (const { param, input } of Object.values(paramInputs)) {
          const val = input.value.trim();
          if (param.in === 'path') {
            finalPath = finalPath.replace('{' + param.name + '}', encodeURIComponent(val || param.name));
          } else if (param.in === 'query' && val !== '') {
            query.set(param.name, val);
          } else if (param.in === 'header' && val !== '') {
            headers[param.name] = val;
          }
        }
        if (csrfInput.value.trim()) headers['X-CSRF-Token'] = csrfInput.value.trim();
        const qs = query.toString();
        const targetUrl = base + finalPath + (qs ? '?' + qs : '');
        const fetchOpts = { method: op.method, headers, credentials: 'same-origin' };
        if (bodyTextarea && op.method !== 'GET' && op.method !== 'HEAD') {
          headers['Content-Type'] = contentType;
          fetchOpts.body = bodyTextarea.value;
        }
        resultWrap.classList.remove('hidden');
        statusLine.textContent = 'Requesting ' + op.method + ' ' + targetUrl + '...';
        resultPre.textContent = '';
        try {
          const resp = await fetch(targetUrl, fetchOpts);
          const ct = resp.headers.get('content-type') || '';
          statusLine.textContent = 'HTTP ' + resp.status + ' ' + resp.statusText + (ct ? ' (' + ct + ')' : '');
          const text = await resp.text();
          if (ct.includes('json')) {
            try {
              resultPre.textContent = JSON.stringify(JSON.parse(text), null, 2);
            } catch (_) {
              resultPre.textContent = text.slice(0, 16384);
            }
          } else {
            resultPre.textContent = text.slice(0, 16384);
          }
        } catch (err) {
          statusLine.textContent = 'Request failed';
          resultPre.textContent = String(err && err.message ? err.message : err);
        }
      },
    });

    box.appendChild(el('div', { className: 'actions' }, runBtn));
    box.appendChild(resultWrap);
    return box;
  }

  function renderOperationCard(spec, op, cardKey) {
    const isOpen = state.expandedKeys.has(cardKey);
    const card = el('article', { className: 'op-card' + (isOpen ? ' open' : '') });
    const methodClass = 'method m-' + op.method.toLowerCase();

    const summaryBtn = el('button', {
      type: 'button',
      className: 'op-summary',
      'aria-expanded': isOpen ? 'true' : 'false',
      onClick: () => {
        if (state.expandedKeys.has(cardKey)) state.expandedKeys.delete(cardKey);
        else state.expandedKeys.add(cardKey);
        renderView();
      },
    }, [
      el('div', { className: 'op-left' }, [
        el('span', { className: methodClass, text: op.method }),
        renderPathSpan(op.path),
        op.summary ? el('span', { className: 'op-desc-inline', text: op.summary }) : null,
      ]),
      el('div', { className: 'op-right' }, [
        op.tags.map((t) => el('span', { className: 'pill', text: t })),
        op.isProtected
          ? el('span', { className: 'lock-badge lock-protected', text: 'Lock: ' + op.securityNames.join(', ') })
          : el('span', { className: 'lock-badge lock-public', text: 'Public' }),
        el('span', { className: 'muted mono', text: isOpen ? '[-]' : '[+]' }),
      ].flat()),
    ]);
    card.appendChild(summaryBtn);

    if (!isOpen) return card;

    const details = el('div', { className: 'op-details' });
    if (op.description) {
      details.appendChild(el('div', null, [
        el('div', { className: 'section-label', text: 'Description' }),
        el('p', { className: 'op-full-desc', text: op.description }),
      ]));
    }

    if (op.parameters.length > 0) {
      const pRows = op.parameters.map((p) => {
        const schema = deref(spec, p.schema || {});
        const typeStr = describeSchemaType(spec, p.schema || {}, 0);
        const extra = schemaConstraints(schema);
        const desc = [p.description || '', extra].filter(Boolean).join(' — ');
        return el('tr', null, [
          el('td', null, [
            el('code', { text: p.name || '' }),
            p.required ? el('span', { className: 'req-star', text: '*' }) : null,
          ]),
          el('td', null, el('span', { className: 'pill', text: p.in || 'query' })),
          el('td', null, el('code', { className: 'muted', text: typeStr })),
          el('td', { className: 'muted', text: desc || '—' }),
        ]);
      });
      details.appendChild(el('div', null, [
        el('div', { className: 'section-label', text: 'Parameters' }),
        el('table', { className: 'spec-table' }, [
          el('thead', null, el('tr', null, [
            el('th', { text: 'Name' }),
            el('th', { text: 'In' }),
            el('th', { text: 'Schema' }),
            el('th', { text: 'Description' }),
          ])),
          el('tbody', null, pRows),
        ]),
      ]));
    }

    if (op.requestBody && op.requestBody.content) {
      const rbChildren = [
        el('div', {
          className: 'section-label',
          text: 'Request Body' + (op.requestBody.required ? ' (Required)' : ' (Optional)'),
        }),
      ];
      for (const [ctype, media] of Object.entries(op.requestBody.content)) {
        rbChildren.push(el('div', { style: 'margin-bottom:8px;' }, [
          el('span', { className: 'pill pill-indigo', text: ctype }),
          media && media.schema ? el('span', { className: 'muted mono', style: 'margin-left:8px;font-size:12px;', text: describeSchemaType(spec, media.schema, 0) }) : null,
        ]));
        if (media && media.schema) {
          const tbl = renderSchemaTable(spec, media.schema);
          if (tbl) rbChildren.push(tbl);
          if (ctype.includes('json')) {
            const sample = sampleFromSchema(spec, media.schema, 0);
            rbChildren.push(el('pre', { className: 'code-block', style: 'margin-top:8px;', text: JSON.stringify(sample, null, 2) }));
          }
        }
      }
      details.appendChild(el('div', null, rbChildren));
    }

    const respEntries = Object.entries(op.responses || {});
    if (respEntries.length > 0) {
      const rRows = respEntries.map(([code, rawResp]) => {
        const resp = deref(spec, rawResp) || {};
        const codeNum = parseInt(code, 10);
        let pillCls = 'pill ';
        if (codeNum >= 200 && codeNum < 300) pillCls += 'pill-emerald';
        else if (codeNum >= 300 && codeNum < 400) pillCls += 'pill-sky';
        else if (codeNum >= 400 && codeNum < 500) pillCls += 'pill-amber';
        else if (codeNum >= 500) pillCls += 'pill-rose';

        const mediaNotes = [];
        if (resp.headers && typeof resp.headers === 'object') {
          for (const [hName, hObj] of Object.entries(resp.headers)) {
            mediaNotes.push(el('div', { className: 'muted', style: 'margin-top:4px;' }, [
              el('code', { text: 'Header ' + hName }),
              document.createTextNode(': ' + ((hObj && hObj.description) || describeSchemaType(spec, hObj && hObj.schema, 0))),
            ]));
          }
        }
        if (resp.content && typeof resp.content === 'object') {
          for (const [ctype, media] of Object.entries(resp.content)) {
            const schemaLabel = media && media.schema ? describeSchemaType(spec, media.schema, 0) : '';
            mediaNotes.push(el('div', { style: 'margin-top:6px;' }, [
              el('span', { className: 'pill', text: ctype }),
              schemaLabel ? el('code', { className: 'muted', style: 'margin-left:8px;', text: schemaLabel }) : null,
            ]));
            if (media && media.schema && ctype.includes('json')) {
              const sample = sampleFromSchema(spec, media.schema, 0);
              mediaNotes.push(el('pre', { className: 'code-block', style: 'margin-top:6px;', text: JSON.stringify(sample, null, 2) }));
            }
          }
        }

        return el('tr', null, [
          el('td', { style: 'width:90px;' }, el('span', { className: pillCls, text: code })),
          el('td', null, [
            el('div', { text: resp.description || '—' }),
            ...mediaNotes,
          ]),
        ]);
      });
      details.appendChild(el('div', null, [
        el('div', { className: 'section-label', text: 'Responses' }),
        el('table', { className: 'spec-table' }, [
          el('thead', null, el('tr', null, [
            el('th', { text: 'Status' }),
            el('th', { text: 'Response Contract' }),
          ])),
          el('tbody', null, rRows),
        ]),
      ]));
    }

    const tryWrap = el('div');
    const tryToggle = el('button', {
      type: 'button',
      className: 'btn',
      text: 'Try It Out',
    });
    let tryBox = null;
    tryToggle.addEventListener('click', () => {
      if (!tryBox) {
        tryBox = buildTryItOut(spec, op);
        tryWrap.appendChild(tryBox);
        tryToggle.textContent = 'Hide Try It Out';
      } else {
        tryBox.classList.toggle('hidden');
        tryToggle.textContent = tryBox.classList.contains('hidden') ? 'Try It Out' : 'Hide Try It Out';
      }
    });
    tryWrap.appendChild(el('div', { style: 'margin-bottom:8px;' }, tryToggle));
    details.appendChild(tryWrap);

    card.appendChild(details);
    return card;
  }

  function renderSchemas(spec) {
    const root = document.getElementById('schemas-root');
    const countEl = document.getElementById('schemas-count');
    root.textContent = '';
    const schemas = (spec && spec.components && spec.components.schemas) || {};
    const entries = Object.entries(schemas);
    countEl.textContent = entries.length + ' schemas';
    for (const [name, schema] of entries) {
      const details = el('details', { className: 'schema-card' });
      const summary = el('summary', null, [
        el('span', { text: name }),
        el('span', { className: 'pill', text: schema.type || 'object' }),
      ]);
      details.appendChild(summary);
      const tbl = renderSchemaTable(spec, schema);
      if (tbl) {
        tbl.style.marginTop = '10px';
        details.appendChild(tbl);
      } else {
        details.appendChild(el('pre', {
          className: 'code-block',
          style: 'margin-top:10px;',
          text: JSON.stringify(schema, null, 2),
        }));
      }
      root.appendChild(details);
    }
  }

  function matchesFilter(op) {
    if (state.selectedMethod !== 'ALL' && op.method !== state.selectedMethod) return false;
    if (state.selectedAuth === 'PROTECTED' && !op.isProtected) return false;
    if (state.selectedAuth === 'PUBLIC' && op.isProtected) return false;
    if (state.selectedTag !== 'ALL' && !op.tags.includes(state.selectedTag)) return false;
    if (state.searchQuery) {
      const q = state.searchQuery.toLowerCase();
      const hay = [
        op.method,
        op.path,
        op.summary,
        op.description,
        op.tags.join(' '),
        op.parameters.map((p) => p.name || '').join(' '),
      ].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  function renderView() {
    const spec = state.spec;
    if (!spec) return;
    const allOps = collectOperations(spec);

    const tagDefs = new Map();
    if (Array.isArray(spec.tags)) {
      for (const t of spec.tags) {
        if (t && t.name) tagDefs.set(t.name, t.description || '');
      }
    }
    for (const op of allOps) {
      for (const t of op.tags) {
        if (!tagDefs.has(t)) tagDefs.set(t, '');
      }
    }

    const tagCounts = new Map();
    for (const op of allOps) {
      for (const t of op.tags) {
        tagCounts.set(t, (tagCounts.get(t) || 0) + 1);
      }
    }

    const nav = document.getElementById('tag-nav');
    nav.textContent = '';
    const allBtn = el('button', {
      type: 'button',
      className: 'nav-item' + (state.selectedTag === 'ALL' ? ' active' : ''),
      onClick: () => { state.selectedTag = 'ALL'; renderView(); },
    }, [
      el('span', { text: 'All Endpoints' }),
      el('span', { className: 'nav-count', text: String(allOps.length) }),
    ]);
    nav.appendChild(allBtn);
    for (const [tName] of tagDefs.entries()) {
      const count = tagCounts.get(tName) || 0;
      if (count === 0) continue;
      nav.appendChild(el('button', {
        type: 'button',
        className: 'nav-item' + (state.selectedTag === tName ? ' active' : ''),
        onClick: () => { state.selectedTag = tName; renderView(); },
      }, [
        el('span', { text: tName }),
        el('span', { className: 'nav-count', text: String(count) }),
      ]));
    }

    const filteredOps = allOps.filter(matchesFilter);
    const protectedCount = allOps.filter((o) => o.isProtected).length;
    document.getElementById('stats-row').textContent =
      'Showing ' + filteredOps.length + ' of ' + allOps.length + ' operations (' +
      protectedCount + ' authenticated, ' + (allOps.length - protectedCount) + ' public) across ' +
      Object.keys(spec.paths || {}).length + ' paths';

    const root = document.getElementById('endpoints-root');
    root.textContent = '';

    if (filteredOps.length === 0) {
      root.appendChild(el('div', { className: 'card' }, el('span', { className: 'muted', text: 'No operations match the active filter.' })));
      return;
    }

    const displayTags = state.selectedTag === 'ALL' ? Array.from(tagDefs.keys()) : [state.selectedTag];
    for (const tag of displayTags) {
      const tagOps = filteredOps.filter((o) => o.tags.includes(tag));
      if (tagOps.length === 0) continue;
      const section = el('section', { className: 'tag-section', style: 'margin-bottom:20px;' });
      const desc = tagDefs.get(tag) || '';
      section.appendChild(el('div', { className: 'tag-header' }, [
        el('h2', null, [
          document.createTextNode(tag),
          el('span', { className: 'pill', text: String(tagOps.length) }),
        ]),
        desc ? el('span', { className: 'tag-desc', text: desc }) : null,
      ]));
      for (const op of tagOps) {
        const cardKey = tag + '::' + op.key;
        section.appendChild(renderOperationCard(spec, op, cardKey));
      }
      root.appendChild(section);
    }
  }

  function applySpecMetadata(spec) {
    const info = spec.info || {};
    document.getElementById('api-title').textContent = info.title || 'AetherFlow API';
    document.getElementById('spec-version').textContent = 'OpenAPI ' + (spec.openapi || '3.1.0');
    document.getElementById('api-version').textContent = 'v' + (info.version || '1.0.0');

    const schemes = (spec.components && spec.components.securitySchemes) ? Object.keys(spec.components.securitySchemes) : [];
    const secPill = document.getElementById('security-pill');
    secPill.textContent = schemes.length > 0 ? schemes.join(', ') : 'Public';

    const banner = document.getElementById('info-banner');
    const infoDesc = document.getElementById('info-desc');
    if (info.description) {
      renderRichInline(infoDesc, info.description);
      banner.classList.remove('hidden');
    } else {
      banner.classList.add('hidden');
    }

    const sel = document.getElementById('server-select');
    sel.textContent = '';
    const servers = Array.isArray(spec.servers) && spec.servers.length > 0
      ? spec.servers
      : [{ url: '/api/v1', description: 'Canonical v1' }];
    const onLegacyPrefix = window.location.pathname.startsWith('/api/public/');
    for (const s of servers) {
      const opt = el('option', {
        value: s.url || '/api/v1',
        text: (s.url || '/api/v1') + (s.description ? ' (' + s.description + ')' : ''),
      });
      if (onLegacyPrefix && s.url === '/api') opt.selected = true;
      sel.appendChild(opt);
    }
  }

  async function loadSpec() {
    const errBox = document.getElementById('error-box');
    const errMsg = document.getElementById('error-msg');
    errBox.classList.add('hidden');
    const dl = document.getElementById('download-spec-link');
    dl.setAttribute('href', state.specUrl);
    try {
      const resp = await fetch(state.specUrl, { credentials: 'same-origin' });
      if (!resp.ok) throw new Error('HTTP ' + resp.status + ' fetching ' + state.specUrl);
      const raw = await resp.text();
      state.rawYaml = raw;
      document.getElementById('raw-yaml-pre').textContent = raw;
      state.spec = parseYaml(raw);
      applySpecMetadata(state.spec);
      renderSchemas(state.spec);
      renderView();
    } catch (err) {
      errMsg.textContent = String(err && err.message ? err.message : err);
      errBox.classList.remove('hidden');
      document.getElementById('stats-row').textContent = 'Unavailable';
    }
  }

  document.getElementById('search-input').addEventListener('input', (e) => {
    state.searchQuery = e.target.value.trim();
    renderView();
  });

  document.getElementById('method-filters').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-method]');
    if (!btn) return;
    state.selectedMethod = btn.getAttribute('data-method');
    for (const c of document.querySelectorAll('#method-filters .chip')) {
      c.classList.toggle('active', c === btn);
    }
    renderView();
  });

  document.getElementById('auth-filters').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-auth]');
    if (!btn) return;
    state.selectedAuth = btn.getAttribute('data-auth');
    for (const c of document.querySelectorAll('#auth-filters .chip')) {
      c.classList.toggle('active', c === btn);
    }
    renderView();
  });

  document.getElementById('btn-expand-all').addEventListener('click', () => {
    if (!state.spec) return;
    const ops = collectOperations(state.spec).filter(matchesFilter);
    const displayTags = state.selectedTag === 'ALL'
      ? Array.from(new Set(ops.flatMap((o) => o.tags)))
      : [state.selectedTag];
    for (const tag of displayTags) {
      for (const op of ops) {
        if (op.tags.includes(tag)) state.expandedKeys.add(tag + '::' + op.key);
      }
    }
    renderView();
  });

  document.getElementById('btn-collapse-all').addEventListener('click', () => {
    state.expandedKeys.clear();
    renderView();
  });

  const modal = document.getElementById('raw-modal');
  document.getElementById('btn-raw-yaml').addEventListener('click', () => modal.classList.add('open'));
  document.getElementById('btn-close-modal').addEventListener('click', () => modal.classList.remove('open'));
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.classList.remove('open');
  });
  document.getElementById('btn-copy-yaml').addEventListener('click', async () => {
    if (navigator.clipboard && state.rawYaml) {
      try {
        await navigator.clipboard.writeText(state.rawYaml);
        document.getElementById('btn-copy-yaml').textContent = 'Copied';
        setTimeout(() => { document.getElementById('btn-copy-yaml').textContent = 'Copy YAML'; }, 1500);
      } catch (_) {}
    }
  });

  document.getElementById('btn-retry').addEventListener('click', loadSpec);

  loadSpec();
})();
</script>
</body>
</html>
"####;
