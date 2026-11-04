import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer


def read_env_config():
    bind_addr = os.environ.get("PLUGIN_BIND_ADDR", "127.0.0.1").strip() or "127.0.0.1"
    raw_port = os.environ.get("PLUGIN_PORT") or os.environ.get("PORT") or "21000"
    port = int(raw_port)
    plugin_id = os.environ.get("PLUGIN_ID", "telemetry-inspector").strip() or "telemetry-inspector"
    plugin_name = os.environ.get("PLUGIN_NAME", "Telemetry Inspector").strip() or "Telemetry Inspector"
    plugin_version = os.environ.get("PLUGIN_VERSION", "1.0.0").strip() or "1.0.0"
    api_base_url = (
        os.environ.get("AETHERFLOW_API_BASE_URL", "http://127.0.0.1:8080").strip().rstrip("/")
        or "http://127.0.0.1:8080"
    )
    plugin_token = os.environ.get("AETHERFLOW_PLUGIN_TOKEN", "").strip()
    return {
        "bind_addr": bind_addr,
        "port": port,
        "plugin_id": plugin_id,
        "plugin_name": plugin_name,
        "plugin_version": plugin_version,
        "api_base_url": api_base_url,
        "plugin_token": plugin_token,
    }


def probe_host_endpoint(url, bearer_token=None):
    headers = {"Accept": "application/json"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    request_obj = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request_obj, timeout=3.0) as response:
            raw_body = response.read().decode("utf-8", errors="replace")
            parsed_body = json.loads(raw_body) if raw_body.strip() else None
            return response.status, parsed_body
    except urllib.error.HTTPError as http_err:
        return http_err.code, None
    except Exception:
        return 502, None


class TelemetryInspectorHandler(BaseHTTPRequestHandler):
    def log_message(self, format_str, *args):
        return

    def send_json(self, status_code, payload):
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        config = read_env_config()
        route_path = self.path.split("?", 1)[0]
        lower_headers = {key.lower(): val for key, val in self.headers.items()}
        had_cookie = "cookie" in lower_headers
        had_auth = "authorization" in lower_headers
        forwarded_plugin = lower_headers.get("x-aetherflow-plugin-id", "")
        forwarded_user = lower_headers.get("x-aetherflow-user", "")

        if route_path in ("/healthz", "/status"):
            self.send_json(
                200,
                {
                    "status": "ok",
                    "plugin_id": config["plugin_id"],
                    "plugin_name": config["plugin_name"],
                    "version": config["plugin_version"],
                    "sdk": "managed-sample",
                    "runtime_mode": "managed",
                    "listen_port": config["port"],
                    "auth_token_configured": bool(config["plugin_token"]),
                    "proxied_plugin_header": forwarded_plugin,
                    "forwarded_user": forwarded_user,
                    "had_cookie_header": had_cookie,
                    "had_authorization_header": had_auth,
                },
            )
            return

        if route_path == "/snapshot":
            mkt_status, mkt_payload = probe_host_endpoint(
                f"{config['api_base_url']}/api/v1/public/marketplace"
            )
            metrics_status, metrics_payload = probe_host_endpoint(
                f"{config['api_base_url']}/api/v1/auth/system/metrics",
                config["plugin_token"],
            )
            marketplace_count = 0
            if isinstance(mkt_payload, list):
                marketplace_count = len(mkt_payload)
            elif isinstance(mkt_payload, dict) and isinstance(mkt_payload.get("packages"), list):
                marketplace_count = len(mkt_payload["packages"])

            self.send_json(
                200,
                {
                    "status": "ok",
                    "plugin_id": config["plugin_id"],
                    "runtime_mode": "managed",
                    "listen_port": config["port"],
                    "auth_token_configured": bool(config["plugin_token"]),
                    "marketplace_status": mkt_status,
                    "marketplace_count": marketplace_count,
                    "metrics_status": metrics_status,
                    "metrics_sampled": isinstance(metrics_payload, dict),
                    "had_cookie_header": had_cookie,
                    "had_authorization_header": had_auth,
                },
            )
            return

        self.send_json(
            404,
            {
                "error": "NOT_FOUND",
                "path": route_path,
                "plugin_id": config["plugin_id"],
            },
        )


def main():
    config = read_env_config()
    server = HTTPServer((config["bind_addr"], config["port"]), TelemetryInspectorHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
