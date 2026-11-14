#!/usr/bin/env python3
"""Cryptographic Sigstore + SLSA v1 provenance verifier for AetherFlow v4+ releases.

Zero external PyPI dependencies: uses only Python 3 stdlib + OpenSSL CLI against
pinned Sigstore Public Good Fulcio Root/Intermediate CAs, Rekor v1/v2 Transparency Log
public keys, and Sigstore RFC 3161 Timestamp Authority (TSA) certificates.
"""

from __future__ import annotations

import argparse
import base64
import calendar
import email.utils
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

SAFE_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SAFE_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
V4_RELEASE_TAG_RE = re.compile(
    r"^v(?:[4-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*)?$"
)
PROTECTED_WORKFLOW_REF_RE = re.compile(
    r"^refs/(?:heads/[Nn]ightly|tags/v(?:[4-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*)?)$"
)

# ASN.1 DER OID 1.3.6.1.4.1.57264.1.11 (Fulcio Runner Environment extension)
FULCIO_RUNNER_ENV_OID_DER = b"\x06\x0a\x2b\x06\x01\x04\x01\x83\xbf\x30\x01\x0b"

# Pinned Sigstore Public Good Fulcio Root & Intermediate CAs (from sigstore/root-signing trusted_root.json)
SIGSTORE_FULCIO_ROOTS_B64 = (
    "MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==",
    "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ",
)

SIGSTORE_FULCIO_INTERMEDIATES_B64 = (
    "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow=",
)

# Pinned Sigstore Public Good RFC 3161 Timestamp Authority (TSA) Root & Signing Certs (trusted_root.json)
SIGSTORE_TSA_ROOTS_B64 = (
    "MIIB9zCCAXygAwIBAgIUV7f0GLDOoEzIh8LXSW80OJiUp14wCgYIKoZIzj0EAwMwOTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Etc2VsZnNpZ25lZDAeFw0yNTA0MDgwNjU5NDNaFw0zNTA0MDYwNjU5NDNaMDkxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEgMB4GA1UEAxMXc2lnc3RvcmUtdHNhLXNlbGZzaWduZWQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQUQNtfRT/ou3YATa6wB/kKTe70cfJwyRIBovMnt8RcJph/COE82uyS6FmppLLL1VBPGcPfpQPYJNXzWwi8icwhKQ6W/Qe2h3oebBb2FHpwNJDqo+TMaC/tdfkv/ElJB72jRTBDMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSY7AHvf7tR/9SVHm+KiJhTB4nOvzAKBggqhkjOPQQDAwNpADBmAjEAwGEGrfGZR1cen1R8/DTVMI943LssZmJRtDp/i7SfGHmGRP6gRbuj9vOK3b67Z0QQAjEAuT2H673LQEaHTcyQSZrkp4mX7WwkmF+sVbkYY5mXN+RMH13KUEHHOqASaemYWK/E",
)

SIGSTORE_TSA_LEAVES_B64 = (
    "MIICEDCCAZagAwIBAgIUOhNULwyQYe68wUMvy4qOiyojiwwwCgYIKoZIzj0EAwMwOTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Etc2VsZnNpZ25lZDAeFw0yNTA0MDgwNjU5NDNaFw0zNTA0MDYwNjU5NDNaMC4xFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEVMBMGA1UEAxMMc2lnc3RvcmUtdHNhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4ra2Z8hKNig2T9kFjCAToGG30jky+WQv3BzL+mKvh1SKNR/UwuwsfNCg4sryoYAd8E6isovVA3M4aoNdm9QDi50Z8nTEyvqgfDPtTIwXItfiW/AFf1V7uwkbkAoj0xxco2owaDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFIn9eUOHz9BlRsMCRscsc1t9tOsDMB8GA1UdIwQYMBaAFJjsAe9/u1H/1JUeb4qImFMHic6/MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqGSM49BAMDA2gAMGUCMDtpsV/6KaO0qyF/UMsX2aSUXKQFdoGTptQGc0ftq1csulHPGG6dsmyMNd3JB+G3EQIxAOajvBcjpJmKb4Nv+2Taoj8Uc5+b6ih6FXCCKraSqupe07zqswMcXJTe1cExvHvvlw==",
)

# Pinned Sigstore Public Good Rekor v1 & v2 Transparency Log public keys:
# keyId -> (spki_b64, key_type, expected_origin)
SIGSTORE_REKOR_KEYS = {
    "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=": (
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==",
        "PKIX_ECDSA_P256_SHA_256",
        "rekor.sigstore.dev",
    ),
    "zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=": (
        "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=",
        "PKIX_ED25519",
        "log2025-1.rekor.sigstore.dev",
    ),
    "tUgTy2PYhZhwpeeFAMxq3P31lyPtrpPujSX68kdaBpA=": (
        "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=",
        "PKIX_ED25519",
        "log2025-1.rekor.sigstore.dev",
    ),
}


class ProvenanceVerificationError(Exception):
    """Raised when cryptographic provenance verification fails."""


def _wrap_pem(label: str, raw_b64: str) -> str:
    der = base64.b64decode(raw_b64)
    encoded = base64.encodebytes(der).decode("ascii")
    return f"-----BEGIN {label}-----\n{encoded}-----END {label}-----\n"


def _resolve_github_token() -> str | None:
    for key in ("AF_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return None


def _is_trusted_github_https_url(candidate_url: str) -> bool:
    parsed = urllib.parse.urlsplit(candidate_url)
    if parsed.scheme.lower() != "https":
        return False
    host = (parsed.hostname or "").lower().rstrip(".")
    return (
        host in ("api.github.com", "github.com")
        or host.endswith(".githubusercontent.com")
    )


class _StripAuthCrossOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            return None
        orig = urllib.parse.urlsplit(req.full_url)
        dest = urllib.parse.urlsplit(redirected.full_url)
        same_https_origin = (
            orig.scheme.lower() == "https"
            and dest.scheme.lower() == "https"
            and (orig.hostname or "").lower() == (dest.hostname or "").lower()
            and (orig.port or 443) == (dest.port or 443)
        )
        if not same_https_origin or not _is_trusted_github_https_url(redirected.full_url):
            for header_dict in (redirected.headers, redirected.unredirected_hdrs):
                for key in list(header_dict.keys()):
                    if key.lower() == "authorization":
                        header_dict.pop(key, None)
        return redirected


def _fetch_attestations(api_base_url: str, repo: str, digest: str) -> list[dict]:
    url = f"{api_base_url.rstrip('/')}/repos/{repo}/attestations/sha256:{digest}?per_page=30"
    parsed_url = urllib.parse.urlsplit(url)
    if parsed_url.scheme.lower() != "https":
        raise ProvenanceVerificationError(
            f"refusing non-HTTPS provenance API URL: {url!r}"
        )
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "AetherFlow-ProvenanceVerifier/4.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = _resolve_github_token()
    if token and _is_trusted_github_https_url(url):
        headers["Authorization"] = f"Bearer {token}"

    opener = urllib.request.build_opener(_StripAuthCrossOriginRedirectHandler())
    last_exc: Exception | None = None
    for attempt in range(3):
        req = urllib.request.Request(url, headers=headers)
        try:
            with opener.open(req, timeout=30) as resp:
                raw = resp.read(16 * 1024 * 1024 + 1)
                if len(raw) > 16 * 1024 * 1024:
                    raise ProvenanceVerificationError("attestation response exceeds 16 MiB limit")
                data = json.loads(raw.decode("utf-8"))
                break
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 500, 502, 503, 504) and attempt < 2:
                last_exc = exc
                time.sleep(1.5 * (attempt + 1))
                continue
            raise ProvenanceVerificationError(
                f"GitHub attestations API HTTP {exc.code} for {repo}@sha256:{digest}"
            ) from exc
        except Exception as exc:
            if attempt < 2:
                last_exc = exc
                time.sleep(1.5 * (attempt + 1))
                continue
            raise ProvenanceVerificationError(
                f"failed to fetch GitHub attestations for {repo}@sha256:{digest}: {exc}"
            ) from exc
    else:
        raise ProvenanceVerificationError(
            f"failed to fetch GitHub attestations for {repo}@sha256:{digest}: {last_exc}"
        )

    return _extract_bundles(data)


def _extract_bundles(data: object) -> list[dict]:
    if not isinstance(data, dict):
        raise ProvenanceVerificationError("attestation payload must be a JSON object")
    if isinstance(data.get("attestations"), list):
        bundles = []
        for item in data["attestations"]:
            if isinstance(item, dict) and isinstance(item.get("bundle"), dict):
                bundles.append(item["bundle"])
        return bundles
    if isinstance(data.get("bundle"), dict):
        return [data["bundle"]]
    if isinstance(data.get("verificationMaterial"), dict) and isinstance(data.get("dsseEnvelope"), dict):
        return [data]
    return []


def _parse_openssl_asn1_time(raw: str) -> int:
    # Normalize optional fractional seconds: "Nov 14 08:03:25.123456 2026 GMT"
    cleaned = re.sub(r"(\d{2}:\d{2}:\d{2})\.\d+", r"\1", raw.strip())
    parsed = email.utils.parsedate_tz(cleaned)
    if parsed is not None:
        return int(email.utils.mktime_tz(parsed))
    dt = time.strptime(cleaned, "%b %d %H:%M:%S %Y %Z")
    return int(calendar.timegm(dt))


def _read_der_length(buf: bytes, idx: int) -> tuple[int, int]:
    if idx >= len(buf):
        raise ProvenanceVerificationError("truncated ASN.1 DER length")
    first = buf[idx]
    idx += 1
    if (first & 0x80) == 0:
        return first, idx
    num_octets = first & 0x7F
    if num_octets == 0 or num_octets > 4 or idx + num_octets > len(buf):
        raise ProvenanceVerificationError("invalid ASN.1 DER long-form length")
    length = int.from_bytes(buf[idx : idx + num_octets], "big")
    return length, idx + num_octets


def _extract_fulcio_runner_environment(leaf_der: bytes) -> str | None:
    pos = 0
    while True:
        found = leaf_der.find(FULCIO_RUNNER_ENV_OID_DER, pos)
        if found == -1:
            return None
        cursor = found + len(FULCIO_RUNNER_ENV_OID_DER)
        pos = found + 1
        try:
            # Optional BOOLEAN critical flag (0x01 0x01 <bool>)
            if cursor + 3 <= len(leaf_der) and leaf_der[cursor] == 0x01 and leaf_der[cursor + 1] == 0x01:
                cursor += 3
            if cursor >= len(leaf_der) or leaf_der[cursor] != 0x04:
                continue
            octet_len, cursor = _read_der_length(leaf_der, cursor + 1)
            if cursor + octet_len > len(leaf_der):
                continue
            ext_val = leaf_der[cursor : cursor + octet_len]
            # Fulcio v2 wraps value in DER UTF8String (0x0C) or IA5String (0x16); v1 uses raw UTF-8
            if ext_val and ext_val[0] in (0x0C, 0x16):
                str_len, inner = _read_der_length(ext_val, 1)
                if inner + str_len == len(ext_val):
                    return ext_val[inner : inner + str_len].decode("utf-8", errors="strict")
            return ext_val.decode("utf-8", errors="strict")
        except Exception:
            continue


def _verify_signature_with_openssl(
    td: Path,
    pub_pem: str,
    key_details: str,
    message: bytes,
    signature: bytes,
    tag: str,
) -> None:
    pub_path = td / f"{tag}-pub.pem"
    msg_path = td / f"{tag}-msg.bin"
    sig_path = td / f"{tag}-sig.bin"
    pub_path.write_text(pub_pem, encoding="utf-8")
    msg_path.write_bytes(message)
    sig_path.write_bytes(signature)

    if key_details == "PKIX_ED25519":
        cmd = [
            "openssl",
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(pub_path),
            "-rawin",
            "-in",
            str(msg_path),
            "-sigfile",
            str(sig_path),
        ]
    else:
        cmd = [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(pub_path),
            "-signature",
            str(sig_path),
            str(msg_path),
        ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if res.returncode != 0:
        raise ProvenanceVerificationError(
            f"OpenSSL signature verification failed ({tag}): {res.stderr.strip() or res.stdout.strip()}"
        )


def _verify_rfc3161_timestamps(
    td: Path,
    vm: dict,
    raw_dsse_sig: bytes,
    tsa_roots_b64: tuple[str, ...] = SIGSTORE_TSA_ROOTS_B64,
    tsa_leaves_b64: tuple[str, ...] = SIGSTORE_TSA_LEAVES_B64,
) -> list[int]:
    ts_data = vm.get("timestampVerificationData")
    if not isinstance(ts_data, dict):
        return []
    rfc_list = ts_data.get("rfc3161Timestamps")
    if not isinstance(rfc_list, list) or not rfc_list:
        return []

    tsa_roots_path = td / "tsa-roots.pem"
    tsa_leaves_path = td / "tsa-leaves.pem"
    sig_data_path = td / "dsse-raw-sig.bin"
    tsa_roots_path.write_text(
        "".join(_wrap_pem("CERTIFICATE", c) for c in tsa_roots_b64),
        encoding="utf-8",
    )
    tsa_leaves_path.write_text(
        "".join(_wrap_pem("CERTIFICATE", c) for c in tsa_leaves_b64),
        encoding="utf-8",
    )
    sig_data_path.write_bytes(raw_dsse_sig)

    verified_times: list[int] = []
    for idx, entry in enumerate(rfc_list):
        if not isinstance(entry, dict) or not isinstance(entry.get("signedTimestamp"), str):
            raise ProvenanceVerificationError(f"malformed rfc3161Timestamps[{idx}]")
        ts_bytes = base64.b64decode(entry["signedTimestamp"])
        ts_path = td / f"rfc3161-{idx}.der"
        ts_path.write_bytes(ts_bytes)

        matched_mode: list[str] | None = None
        last_err = ""
        for token_flags in ([], ["-token_in"]):
            v_cmd = [
                "openssl",
                "ts",
                "-verify",
                "-data",
                str(sig_data_path),
                "-in",
                str(ts_path),
                *token_flags,
                "-CAfile",
                str(tsa_roots_path),
                "-untrusted",
                str(tsa_leaves_path),
            ]
            v_res = subprocess.run(v_cmd, capture_output=True, text=True, timeout=15)
            if v_res.returncode == 0 and "Verification: OK" in (v_res.stdout + v_res.stderr):
                matched_mode = token_flags
                break
            last_err = (v_res.stderr or v_res.stdout).strip()

        if matched_mode is None:
            raise ProvenanceVerificationError(
                f"RFC 3161 TSA verification failed for rfc3161Timestamps[{idx}]: {last_err}"
            )

        r_cmd = ["openssl", "ts", "-reply", "-in", str(ts_path), *matched_mode, "-text"]
        r_res = subprocess.run(r_cmd, capture_output=True, text=True, timeout=10)
        if r_res.returncode != 0:
            raise ProvenanceVerificationError(
                f"failed to inspect RFC 3161 timestamp[{idx}]: {r_res.stderr.strip()}"
            )
        ts_epoch: int | None = None
        for line in r_res.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Time stamp:"):
                ts_epoch = _parse_openssl_asn1_time(stripped.split(":", 1)[1])
                break
        if ts_epoch is None or ts_epoch <= 0:
            raise ProvenanceVerificationError(
                f"RFC 3161 timestamp[{idx}] missing valid generation time"
            )
        verified_times.append(ts_epoch)

    return verified_times


def _verify_merkle_inclusion(
    leaf_hash: bytes,
    log_index: int,
    tree_size: int,
    hashes_b64: list[str],
    expected_root: bytes,
) -> None:
    if log_index < 0 or tree_size <= 0 or log_index >= tree_size:
        raise ProvenanceVerificationError("invalid Rekor Merkle tree bounds")

    fn = log_index
    sn = tree_size - 1
    acc = leaf_hash
    for h_b64 in hashes_b64:
        sibling = base64.b64decode(h_b64)
        if len(sibling) != 32:
            raise ProvenanceVerificationError("invalid Rekor Merkle sibling hash length")
        if sn == 0:
            raise ProvenanceVerificationError("Rekor Merkle proof longer than tree height")
        if (fn & 1) == 1 or fn == sn:
            acc = hashlib.sha256(b"\x01" + sibling + acc).digest()
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            acc = hashlib.sha256(b"\x01" + acc + sibling).digest()
        fn >>= 1
        sn >>= 1

    if sn != 0 or acc != expected_root:
        raise ProvenanceVerificationError("Rekor Merkle inclusion root hash mismatch")


def _extract_der_from_verifier(verifier: object) -> bytes:
    if isinstance(verifier, dict):
        x509_obj = verifier.get("x509Certificate")
        if isinstance(x509_obj, dict) and isinstance(x509_obj.get("rawBytes"), str):
            return _extract_der_from_verifier(x509_obj["rawBytes"])
        pub_obj = verifier.get("publicKey")
        if isinstance(pub_obj, dict) and isinstance(pub_obj.get("rawBytes"), str):
            return _extract_der_from_verifier(pub_obj["rawBytes"])
        if isinstance(verifier.get("content"), str):
            return _extract_der_from_verifier(verifier["content"])
        raise ProvenanceVerificationError("unsupported Rekor verifier object format")
    if not isinstance(verifier, str):
        raise ProvenanceVerificationError("Rekor verifier must be string or object")
    decoded = base64.b64decode(verifier)
    try:
        text = decoded.decode("ascii")
        if "-----BEGIN " in text:
            pem_lines = [
                ln.strip()
                for ln in text.splitlines()
                if ln.strip() and not ln.strip().startswith("-----")
            ]
            return base64.b64decode("".join(pem_lines))
    except UnicodeDecodeError:
        pass
    return decoded


def _normalize_hash_digest_hex(hash_obj: dict) -> tuple[str, str]:
    alg_raw = str(hash_obj.get("algorithm", "")).strip()
    alg_norm = alg_raw.upper()
    if alg_norm in ("SHA2_256", "SHA256", "SHA-256", "1"):
        alg = "sha256"
    else:
        alg = alg_raw.lower()

    if isinstance(hash_obj.get("value"), str) and hash_obj["value"]:
        val = hash_obj["value"].strip().lower()
        if SAFE_HEX64_RE.fullmatch(val):
            return alg, val
        return alg, base64.b64decode(hash_obj["value"]).hex()

    if isinstance(hash_obj.get("digest"), str) and hash_obj["digest"]:
        raw_dig = hash_obj["digest"].strip()
        if SAFE_HEX64_RE.fullmatch(raw_dig):
            return alg, raw_dig.lower()
        return alg, base64.b64decode(raw_dig).hex()

    return alg, ""


def _compute_allowed_checkpoint_key_hints(
    key_id_bytes: bytes,
    spki_der: bytes,
    key_details: str,
    note_origin: str,
) -> set[bytes]:
    hints = {
        key_id_bytes[:4],
        hashlib.sha256(spki_der).digest()[:4],
    }
    if key_details == "PKIX_ED25519" and len(spki_der) >= 32:
        raw_ed25519_pub = spki_der[-32:]
        c2sp_payload = note_origin.encode("utf-8") + b"\n\x01" + raw_ed25519_pub
        hints.add(hashlib.sha256(c2sp_payload).digest()[:4])
    return hints


def _verify_rekor_tlog_entry(
    td: Path,
    tlog: dict,
    expected_payload_sha256: str,
    expected_dsse_sig_b64: str,
    expected_leaf_der: bytes,
    verified_tsa_times: list[int],
    rekor_keys: dict[str, tuple[str, str, str]] = SIGSTORE_REKOR_KEYS,
) -> list[int]:
    log_id_obj = tlog.get("logId")
    if not isinstance(log_id_obj, dict) or not isinstance(log_id_obj.get("keyId"), str):
        raise ProvenanceVerificationError("missing Rekor logId.keyId")
    key_id = log_id_obj["keyId"]
    if key_id not in rekor_keys:
        raise ProvenanceVerificationError(f"untrusted Rekor transparency log keyId: {key_id}")
    spki_b64, key_details, expected_origin = rekor_keys[key_id]
    spki_der = base64.b64decode(spki_b64)
    rekor_pub_pem = _wrap_pem("PUBLIC KEY", spki_b64)
    key_id_bytes = base64.b64decode(key_id)

    try:
        integrated_time = int(tlog.get("integratedTime", 0) or 0)
        log_index = int(tlog["logIndex"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProvenanceVerificationError("missing or invalid Rekor integratedTime/logIndex") from exc
    if integrated_time < 0 or log_index < 0:
        raise ProvenanceVerificationError("out-of-range Rekor integratedTime/logIndex")

    canon_b64 = tlog.get("canonicalizedBody")
    if not isinstance(canon_b64, str) or not canon_b64:
        raise ProvenanceVerificationError("missing Rekor canonicalizedBody")
    canon_bytes = base64.b64decode(canon_b64)
    try:
        canon_obj = json.loads(canon_bytes.decode("utf-8"))
    except Exception as exc:
        raise ProvenanceVerificationError("invalid JSON in Rekor canonicalizedBody") from exc

    if not isinstance(canon_obj, dict):
        raise ProvenanceVerificationError("Rekor canonicalizedBody must decode to a JSON object")
    api_version = str(canon_obj.get("apiVersion", "")).strip()
    kind_ver = tlog.get("kindVersion")
    kv_version = str(kind_ver.get("version", "")).strip() if isinstance(kind_ver, dict) else ""
    is_v2_entry = api_version == "0.0.2" or kv_version == "0.0.2"

    spec = canon_obj.get("spec")
    if not isinstance(spec, dict):
        raise ProvenanceVerificationError("missing spec in Rekor canonicalizedBody")

    # Extract payloadHash & signatures across Rekor v1 (dsse/intoto 0.0.1) and Rekor v2 (dsseV002/intotoV002 0.0.2)
    inner_v2 = spec.get("dsseV002") or spec.get("intotoV002")
    active_spec = inner_v2 if isinstance(inner_v2, dict) else spec
    if isinstance(inner_v2, dict):
        is_v2_entry = True

    payload_hash_obj = active_spec.get("payloadHash")
    if not isinstance(payload_hash_obj, dict) and isinstance(active_spec.get("data"), dict):
        payload_hash_obj = active_spec["data"].get("hash") or active_spec["data"]
    if not isinstance(payload_hash_obj, dict):
        raise ProvenanceVerificationError("Rekor entry lacks payloadHash binding")
    alg, digest_hex = _normalize_hash_digest_hex(payload_hash_obj)
    if alg != "sha256" or digest_hex != expected_payload_sha256:
        raise ProvenanceVerificationError("Rekor payloadHash does not match DSSE payload")

    rekor_sigs = active_spec.get("signatures")
    if not isinstance(rekor_sigs, list) or not rekor_sigs:
        raise ProvenanceVerificationError("Rekor entry lacks signatures binding")

    expected_sig_raw = base64.b64decode(expected_dsse_sig_b64)
    matched_sig_and_cert = False
    for item in rekor_sigs:
        if not isinstance(item, dict):
            continue
        cand = item.get("signature") or item.get("sig") or item.get("content")
        ver = item.get("verifier") or item.get("publicKey")
        if not isinstance(cand, str) or ver is None:
            continue
        try:
            cand_raw = base64.b64decode(cand)
            sig_ok = (
                cand_raw == expected_sig_raw
                or cand_raw == expected_dsse_sig_b64.encode("ascii")
            )
            ver_der = _extract_der_from_verifier(ver)
            if sig_ok and ver_der == expected_leaf_der:
                matched_sig_and_cert = True
                break
        except Exception:
            continue
    if not matched_sig_and_cert:
        raise ProvenanceVerificationError(
            "Rekor entry signature/verifier does not match DSSE signature and leaf certificate"
        )

    # Require RFC 6962 Merkle inclusion proof + signed Rekor checkpoint on both v1 and v2
    proof = tlog.get("inclusionProof")
    if not isinstance(proof, dict) or not isinstance(proof.get("checkpoint"), dict):
        raise ProvenanceVerificationError(
            "Rekor tlogEntry missing required Merkle inclusionProof"
        )
    envelope = proof["checkpoint"].get("envelope")
    hashes = proof.get("hashes")
    root_hash_b64 = proof.get("rootHash")
    if (
        not isinstance(envelope, str)
        or "\n\n" not in envelope
        or not isinstance(hashes, list)
        or not isinstance(root_hash_b64, str)
    ):
        raise ProvenanceVerificationError("malformed Rekor inclusionProof")
    proof_index = int(proof.get("logIndex", -1))
    tree_size = int(proof.get("treeSize", -1))
    if proof_index < 0 or proof_index > log_index:
        raise ProvenanceVerificationError("Rekor inclusionProof shard logIndex invalid")
    expected_root = base64.b64decode(root_hash_b64)
    leaf_hash = hashlib.sha256(b"\x00" + canon_bytes).digest()
    _verify_merkle_inclusion(leaf_hash, proof_index, tree_size, hashes, expected_root)

    note_body, sig_section = envelope.split("\n\n", 1)
    signed_note = (note_body + "\n").encode("utf-8")
    note_lines = note_body.splitlines()
    if len(note_lines) < 3:
        raise ProvenanceVerificationError("Rekor checkpoint note has fewer than 3 lines")
    note_origin = note_lines[0].strip()
    if expected_origin and not (
        note_origin == expected_origin or note_origin.startswith(expected_origin + " - ")
    ):
        raise ProvenanceVerificationError(
            f"Rekor checkpoint origin {note_origin!r} does not match pinned log {expected_origin!r}"
        )
    if int(note_lines[1].strip()) != tree_size:
        raise ProvenanceVerificationError("Rekor checkpoint treeSize mismatch")
    if base64.b64decode(note_lines[2].strip()) != expected_root:
        raise ProvenanceVerificationError("Rekor checkpoint rootHash mismatch")

    allowed_hints = _compute_allowed_checkpoint_key_hints(
        key_id_bytes, spki_der, key_details, note_origin
    )
    checkpoint_verified = False
    for raw_sig_line in sig_section.splitlines():
        line = raw_sig_line.strip()
        if not line:
            continue
        # Checkpoint signature line: "— <origin> <base64(key_hint[4] || sig)>"
        parts = line.split()
        if len(parts) < 3:
            continue
        sig_signer_name = parts[1].strip()
        if expected_origin and sig_signer_name != expected_origin:
            continue
        try:
            hint_and_sig = base64.b64decode(parts[-1])
        except Exception:
            continue
        if len(hint_and_sig) <= 4 or hint_and_sig[:4] not in allowed_hints:
            continue
        _verify_signature_with_openssl(
            td, rekor_pub_pem, key_details, signed_note, hint_and_sig[4:], "rekor-ckpt"
        )
        checkpoint_verified = True
        break
    if not checkpoint_verified:
        raise ProvenanceVerificationError("no valid pinned Rekor signature on checkpoint")

    # Authenticate signing timestamp(s) so short-lived Fulcio leaf cert validity cannot be forged:
    # - Rekor v1 requires signedEntryTimestamp (SET) over (body, integratedTime, logID, logIndex).
    # - Rekor v2 (rekor-tiles) omits SET and sets integratedTime == 0, authenticating time via RFC 3161 TSA.
    authenticated_times: list[int] = list(verified_tsa_times)
    promise = tlog.get("inclusionPromise")
    has_set = isinstance(promise, dict) and isinstance(promise.get("signedEntryTimestamp"), str)
    if has_set:
        if integrated_time <= 0:
            raise ProvenanceVerificationError(
                "Rekor inclusionPromise present with non-positive integratedTime"
            )
        set_sig = base64.b64decode(promise["signedEntryTimestamp"])
        set_payload = json.dumps(
            {
                "body": canon_b64,
                "integratedTime": integrated_time,
                "logID": hashlib.sha256(spki_der).hexdigest(),
                "logIndex": log_index,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        _verify_signature_with_openssl(
            td, rekor_pub_pem, key_details, set_payload, set_sig, "rekor-set"
        )
        authenticated_times.append(integrated_time)
    elif not is_v2_entry:
        raise ProvenanceVerificationError(
            "Rekor v1 tlogEntry missing required inclusionPromise.signedEntryTimestamp"
        )

    if not authenticated_times:
        raise ProvenanceVerificationError(
            "Rekor tlogEntry lacks authenticated signing timestamp (neither verified SET nor RFC 3161 TSA token present)"
        )

    return authenticated_times


def _validate_workflow_ref_policy(
    san_ref: str,
    slsa_ref: str,
    expected_tag: str | None,
    expected_channel: str | None,
) -> None:
    if not san_ref or not PROTECTED_WORKFLOW_REF_RE.fullmatch(san_ref):
        raise ProvenanceVerificationError(
            f"Fulcio SAN workflow ref {san_ref!r} is not a protected nightly branch or v4+ release tag"
        )
    if not slsa_ref or slsa_ref != san_ref:
        raise ProvenanceVerificationError(
            f"SLSA workflow.ref {slsa_ref!r} does not match Fulcio SAN workflow ref {san_ref!r}"
        )

    norm_channel = expected_channel.strip().lower() if expected_channel else None
    if norm_channel == "experimental":
        norm_channel = "nightly"
    if norm_channel and norm_channel not in ("stable", "nightly"):
        raise ProvenanceVerificationError(f"unsupported release channel: {expected_channel!r}")

    if expected_tag is not None:
        tag = expected_tag.strip()
        if not V4_RELEASE_TAG_RE.fullmatch(tag):
            raise ProvenanceVerificationError(
                f"expected release tag {tag!r} does not satisfy v4+ semver floor"
            )
        is_prerelease_tag = "-" in tag
        if norm_channel == "stable" and is_prerelease_tag:
            raise ProvenanceVerificationError(
                f"stable channel cannot verify prerelease tag {tag!r}"
            )
        if norm_channel == "nightly" and not is_prerelease_tag:
            raise ProvenanceVerificationError(
                f"nightly channel requires prerelease tag, got {tag!r}"
            )

        if not is_prerelease_tag:
            expected_exact_ref = f"refs/tags/{tag}"
            if san_ref != expected_exact_ref:
                raise ProvenanceVerificationError(
                    f"stable release {tag!r} requires workflow ref {expected_exact_ref!r}, got {san_ref!r}"
                )
        elif "-nightly." in tag.lower() or norm_channel == "nightly":
            allowed_nightly_refs = {"refs/heads/nightly", "refs/heads/Nightly", f"refs/tags/{tag}"}
            if san_ref not in allowed_nightly_refs:
                raise ProvenanceVerificationError(
                    f"nightly release {tag!r} requires workflow ref in {sorted(allowed_nightly_refs)}, got {san_ref!r}"
                )
        else:
            expected_exact_ref = f"refs/tags/{tag}"
            if san_ref != expected_exact_ref:
                raise ProvenanceVerificationError(
                    f"prerelease tag {tag!r} requires workflow ref {expected_exact_ref!r}, got {san_ref!r}"
                )
    elif norm_channel == "stable":
        if not san_ref.startswith("refs/tags/v") or "-" in san_ref.removeprefix("refs/tags/"):
            raise ProvenanceVerificationError(
                f"stable channel requires non-prerelease tag workflow ref, got {san_ref!r}"
            )
    elif norm_channel == "nightly":
        if san_ref not in ("refs/heads/nightly", "refs/heads/Nightly") and "-nightly." not in san_ref.lower():
            raise ProvenanceVerificationError(
                f"nightly channel requires nightly workflow ref, got {san_ref!r}"
            )


def verify_single_bundle(
    bundle: dict,
    repo: str,
    expected_digest: str,
    artifact_name: str | None,
    expected_tag: str | None = None,
    expected_channel: str | None = None,
    *,
    fulcio_roots_b64: tuple[str, ...] = SIGSTORE_FULCIO_ROOTS_B64,
    fulcio_intermediates_b64: tuple[str, ...] = SIGSTORE_FULCIO_INTERMEDIATES_B64,
    rekor_keys: dict[str, tuple[str, str, str]] = SIGSTORE_REKOR_KEYS,
    tsa_roots_b64: tuple[str, ...] = SIGSTORE_TSA_ROOTS_B64,
    tsa_leaves_b64: tuple[str, ...] = SIGSTORE_TSA_LEAVES_B64,
) -> dict:
    vm = bundle.get("verificationMaterial")
    dsse = bundle.get("dsseEnvelope")
    if not isinstance(vm, dict) or not isinstance(dsse, dict):
        raise ProvenanceVerificationError("bundle missing verificationMaterial or dsseEnvelope")

    # 1. Extract DSSE envelope fields
    payload_type = dsse.get("payloadType")
    if payload_type != "application/vnd.in-toto+json":
        raise ProvenanceVerificationError(f"unexpected DSSE payloadType: {payload_type!r}")
    payload_b64 = dsse.get("payload")
    sigs = dsse.get("signatures")
    if not isinstance(payload_b64, str) or not isinstance(sigs, list) or not sigs:
        raise ProvenanceVerificationError("missing DSSE payload or signatures")
    candidate_sigs: list[tuple[str, bytes]] = []
    for sig_entry in sigs:
        if isinstance(sig_entry, dict):
            sb64 = sig_entry.get("sig")
            if isinstance(sb64, str) and sb64:
                try:
                    candidate_sigs.append((sb64, base64.b64decode(sb64)))
                except Exception:
                    continue
    if not candidate_sigs:
        raise ProvenanceVerificationError("missing DSSE signature bytes")

    raw_payload = base64.b64decode(payload_b64)
    payload_sha256 = hashlib.sha256(raw_payload).hexdigest()

    # 2. Extract leaf & extra intermediate certificates
    extra_inters_b64: list[str] = []
    if isinstance(vm.get("certificate"), dict) and isinstance(vm["certificate"].get("rawBytes"), str):
        leaf_b64 = vm["certificate"]["rawBytes"]
    elif (
        isinstance(vm.get("x509CertificateChain"), dict)
        and isinstance(vm["x509CertificateChain"].get("certificates"), list)
        and vm["x509CertificateChain"]["certificates"]
    ):
        certs = vm["x509CertificateChain"]["certificates"]
        leaf_b64 = certs[0]["rawBytes"]
        for extra in certs[1:]:
            if isinstance(extra, dict) and isinstance(extra.get("rawBytes"), str):
                extra_inters_b64.append(extra["rawBytes"])
    else:
        raise ProvenanceVerificationError("bundle missing X.509 signing certificate")

    tlog_entries = vm.get("tlogEntries")
    if not isinstance(tlog_entries, list) or not tlog_entries:
        raise ProvenanceVerificationError("bundle missing Rekor tlogEntries")

    with tempfile.TemporaryDirectory(prefix="af-prov-") as tmp:
        td = Path(tmp)

        leaf_der = base64.b64decode(leaf_b64)

        # 3a & 3b. Evaluate candidate DSSE signatures against RFC 3161 & Rekor transparency log
        authenticated_times: list[int] | None = None
        verified_raw_sigs: list[bytes] = []
        last_tlog_err: Exception | None = None
        for cand_sig_b64, cand_raw_sig in candidate_sigs:
            verified_tsa_times = _verify_rfc3161_timestamps(
                td, vm, cand_raw_sig, tsa_roots_b64=tsa_roots_b64, tsa_leaves_b64=tsa_leaves_b64
            )
            for entry in tlog_entries:
                if not isinstance(entry, dict):
                    continue
                try:
                    times = _verify_rekor_tlog_entry(
                        td,
                        entry,
                        payload_sha256,
                        cand_sig_b64,
                        leaf_der,
                        verified_tsa_times,
                        rekor_keys=rekor_keys,
                    )
                    if times:
                        if authenticated_times is None:
                            authenticated_times = times
                        verified_raw_sigs.append(cand_raw_sig)
                        break
                except Exception as exc:
                    last_tlog_err = exc
        if not authenticated_times or not verified_raw_sigs:
            raise ProvenanceVerificationError(
                f"no valid Rekor transparency log entry: {last_tlog_err}"
            )

        # 4. Verify Fulcio X.509 certificate chain at every authenticated signing timestamp
        roots_pem = "".join(_wrap_pem("CERTIFICATE", c) for c in fulcio_roots_b64)
        inters_pem = "".join(
            _wrap_pem("CERTIFICATE", c)
            for c in (*fulcio_intermediates_b64, *extra_inters_b64)
        )
        leaf_pem = _wrap_pem("CERTIFICATE", leaf_b64)

        roots_path = td / "roots.pem"
        inters_path = td / "inters.pem"
        leaf_path = td / "leaf.pem"
        roots_path.write_text(roots_pem, encoding="utf-8")
        inters_path.write_text(inters_pem, encoding="utf-8")
        leaf_path.write_text(leaf_pem, encoding="utf-8")

        dates_res = subprocess.run(
            ["openssl", "x509", "-in", str(leaf_path), "-noout", "-dates"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if dates_res.returncode != 0:
            raise ProvenanceVerificationError("failed to parse leaf X.509 certificate dates")
        not_before = None
        not_after = None
        for line in dates_res.stdout.splitlines():
            if line.startswith("notBefore="):
                not_before = _parse_openssl_asn1_time(line.split("=", 1)[1])
            elif line.startswith("notAfter="):
                not_after = _parse_openssl_asn1_time(line.split("=", 1)[1])
        if not_before is None or not_after is None:
            raise ProvenanceVerificationError("leaf X.509 certificate missing validity bounds")

        for auth_time in authenticated_times:
            if not (not_before <= auth_time <= not_after):
                raise ProvenanceVerificationError(
                    f"authenticated timestamp {auth_time} outside leaf cert window [{not_before}, {not_after}]"
                )

        primary_time = authenticated_times[0]
        chain_cmd = [
            "openssl",
            "verify",
            "-attime",
            str(primary_time),
            "-CAfile",
            str(roots_path),
        ]
        if inters_pem.strip():
            chain_cmd.extend(["-untrusted", str(inters_path)])
        chain_cmd.append(str(leaf_path))
        chain_res = subprocess.run(
            chain_cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if chain_res.returncode != 0:
            raise ProvenanceVerificationError(
                f"Fulcio X.509 chain verification failed: {chain_res.stderr.strip() or chain_res.stdout.strip()}"
            )

        # 5. Verify X.509 EKU (Code Signing) + Fulcio GitHub Actions OIDC identity, issuer & runner_environment
        text_res = subprocess.run(
            ["openssl", "x509", "-in", str(leaf_path), "-noout", "-text"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if text_res.returncode != 0:
            raise ProvenanceVerificationError("failed to inspect leaf X.509 extensions")
        cert_text = text_res.stdout

        eku_match = re.search(
            r"X509v3 Extended Key Usage:\s*(?:critical\s*)?\n\s*([^\n]+)",
            cert_text,
        )
        if not eku_match or "Code Signing" not in eku_match.group(1):
            raise ProvenanceVerificationError("leaf certificate missing Code Signing Extended Key Usage")

        # Extract URI SANs under X509v3 Subject Alternative Name
        san_match = re.search(
            r"X509v3 Subject Alternative Name:\s*(?:critical\s*)?\n\s*([^\n]+)",
            cert_text,
        )
        if not san_match:
            raise ProvenanceVerificationError("leaf certificate missing Subject Alternative Name")
        san_line = san_match.group(1).strip()
        expected_uri_prefix = f"uri:https://github.com/{repo.lower()}/.github/workflows/release.yml@"
        san_tokens = [tok.strip() for tok in san_line.split(",")]
        matched_san = next(
            (tok[4:] for tok in san_tokens if tok.lower().startswith(expected_uri_prefix)),
            None,
        )
        if not matched_san:
            raise ProvenanceVerificationError(
                f"leaf SAN {san_line!r} does not match expected workflow URI prefix for {repo}"
            )
        san_ref = matched_san.split("@", 1)[1] if "@" in matched_san else ""

        # Verify Fulcio OIDC Issuer v1 (1.3.6.1.4.1.57264.1.1) or v2 (1.3.6.1.4.1.57264.1.8)
        issuer_match = re.search(
            r"1\.3\.6\.1\.4\.1\.57264\.1\.(?:1|8):\s*(?:critical\s*)?\n\s*([^\n]+)",
            cert_text,
        )
        if not issuer_match or "https://token.actions.githubusercontent.com" not in issuer_match.group(1):
            raise ProvenanceVerificationError(
                "leaf certificate missing GitHub Actions OIDC issuer extension"
            )

        # Verify Fulcio Runner Environment (1.3.6.1.4.1.57264.1.11 == "github-hosted")
        runner_env = _extract_fulcio_runner_environment(leaf_der)
        if runner_env != "github-hosted":
            raise ProvenanceVerificationError(
                f"leaf certificate runner_environment {runner_env!r} is not 'github-hosted'"
            )

        # 6. Verify DSSE PAE cryptographic signature using leaf public key
        pub_res = subprocess.run(
            ["openssl", "x509", "-in", str(leaf_path), "-pubkey", "-noout"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if pub_res.returncode != 0 or "BEGIN PUBLIC KEY" not in pub_res.stdout:
            raise ProvenanceVerificationError("failed to extract leaf public key")

        pt_bytes = payload_type.encode("utf-8")
        pae = (
            f"DSSEv1 {len(pt_bytes)} ".encode("ascii")
            + pt_bytes
            + f" {len(raw_payload)} ".encode("ascii")
            + raw_payload
        )
        pae_verified = False
        last_pae_err: Exception | None = None
        for cand_raw_sig in verified_raw_sigs:
            try:
                _verify_signature_with_openssl(
                    td, pub_res.stdout, "PKIX_ECDSA_P256_SHA_256", pae, cand_raw_sig, "dsse-pae"
                )
                pae_verified = True
                break
            except Exception as exc:
                last_pae_err = exc
        if not pae_verified:
            raise ProvenanceVerificationError(
                f"DSSE PAE signature verification failed: {last_pae_err}"
            )

    # 7. Verify SLSA v1 in-toto statement, subject binding, & workflow ref/tag policy
    try:
        statement = json.loads(raw_payload.decode("utf-8"))
    except Exception as exc:
        raise ProvenanceVerificationError("invalid JSON in DSSE in-toto payload") from exc
    if not isinstance(statement, dict):
        raise ProvenanceVerificationError("in-toto payload must be a JSON object")
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise ProvenanceVerificationError(f"unexpected in-toto _type: {statement.get('_type')!r}")
    if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise ProvenanceVerificationError(
            f"unexpected SLSA predicateType: {statement.get('predicateType')!r}"
        )

    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise ProvenanceVerificationError("in-toto statement contains no subjects")

    expected_basename = PurePosixPath(artifact_name).name if artifact_name else None
    matched_subject = False
    for subj in subjects:
        if not isinstance(subj, dict):
            continue
        digests = subj.get("digest")
        if not isinstance(digests, dict):
            continue
        sha = str(digests.get("sha256", "")).lower()
        if sha != expected_digest:
            continue
        if expected_basename is not None:
            subj_name = PurePosixPath(str(subj.get("name", ""))).name
            if subj_name != expected_basename:
                continue
        matched_subject = True
        break
    if not matched_subject:
        raise ProvenanceVerificationError(
            f"in-toto subjects do not match digest {expected_digest}"
            + (f" and artifact {expected_basename}" if expected_basename else "")
        )

    predicate = statement.get("predicate")
    build_def = predicate.get("buildDefinition") if isinstance(predicate, dict) else None
    ext_params = build_def.get("externalParameters") if isinstance(build_def, dict) else None
    workflow = ext_params.get("workflow") if isinstance(ext_params, dict) else None
    if not isinstance(workflow, dict):
        raise ProvenanceVerificationError("SLSA v1 predicate missing externalParameters.workflow")

    wf_repo = str(workflow.get("repository", "")).rstrip("/").lower()
    if wf_repo != f"https://github.com/{repo.lower()}":
        raise ProvenanceVerificationError(
            f"SLSA workflow repository {wf_repo!r} does not match https://github.com/{repo.lower()}"
        )
    wf_path = str(workflow.get("path", "")).strip()
    if not wf_path or not (
        wf_path == ".github/workflows/release.yml"
        or wf_path.endswith("/.github/workflows/release.yml")
    ):
        raise ProvenanceVerificationError(
            f"SLSA workflow path {wf_path!r} is not .github/workflows/release.yml"
        )

    slsa_ref = str(workflow.get("ref", "")).strip()
    _validate_workflow_ref_policy(san_ref, slsa_ref, expected_tag, expected_channel)

    return {
        "verified": True,
        "repo": repo,
        "digest": expected_digest,
        "workflow_uri": matched_san,
        "workflow_ref": san_ref,
        "integrated_time": primary_time,
    }


def verify_provenance(
    repo: str,
    digest: str,
    artifact_name: str | None = None,
    bundle_file: Path | None = None,
    api_base_url: str | None = None,
    expected_tag: str | None = None,
    expected_channel: str | None = None,
) -> dict:
    repo = repo.strip()
    if not SAFE_REPO_RE.fullmatch(repo):
        raise ProvenanceVerificationError(f"invalid GitHub repository identifier: {repo!r}")
    digest = digest.strip().lower()
    if not SAFE_HEX64_RE.fullmatch(digest):
        raise ProvenanceVerificationError(f"invalid SHA-256 hex digest: {digest!r}")
    if expected_tag is not None and not V4_RELEASE_TAG_RE.fullmatch(expected_tag.strip()):
        raise ProvenanceVerificationError(
            f"invalid or pre-v4 release tag {expected_tag!r} (v4+ semver tag required)"
        )

    if bundle_file is not None:
        raw = bundle_file.read_bytes()
        if len(raw) > 16 * 1024 * 1024:
            raise ProvenanceVerificationError("bundle file exceeds 16 MiB limit")
        bundles = _extract_bundles(json.loads(raw.decode("utf-8")))
    else:
        base_url = (
            api_base_url
            or os.environ.get("AETHERFLOW_GITHUB_API_BASE", "").strip()
            or "https://api.github.com"
        )
        bundles = _fetch_attestations(base_url, repo, digest)

    if not bundles:
        raise ProvenanceVerificationError(
            f"no Sigstore build provenance attestations found for {repo}@sha256:{digest}"
        )

    errors: list[str] = []
    for idx, bundle in enumerate(bundles):
        try:
            return verify_single_bundle(
                bundle,
                repo,
                digest,
                artifact_name,
                expected_tag=expected_tag,
                expected_channel=expected_channel,
            )
        except Exception as exc:
            errors.append(f"bundle[{idx}]: {exc}")

    raise ProvenanceVerificationError(
        f"all {len(bundles)} attestation bundle(s) failed verification: {'; '.join(errors)}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify Sigstore + SLSA v1 GitHub Actions build provenance for an AetherFlow release artifact."
    )
    parser.add_argument("--repo", required=True, help="GitHub owner/repo (e.g. McEveritts/AetherFlow)")
    parser.add_argument("--digest", required=True, help="Expected lowercase 64-hex SHA-256 artifact digest")
    parser.add_argument("--artifact-name", default=None, help="Expected artifact filename")
    parser.add_argument("--tag", default=None, help="Expected v4+ release tag (binds workflow ref)")
    parser.add_argument("--channel", default=None, help="Expected release channel (stable or nightly)")
    parser.add_argument(
        "--bundle-file",
        type=Path,
        default=None,
        help="Optional local JSON attestation bundle file for offline verification",
    )
    parser.add_argument(
        "--api-base-url",
        default=None,
        help="Optional GitHub API base URL override",
    )
    args = parser.parse_args(argv)

    try:
        summary = verify_provenance(
            repo=args.repo,
            digest=args.digest,
            artifact_name=args.artifact_name,
            bundle_file=args.bundle_file,
            api_base_url=args.api_base_url,
            expected_tag=args.tag,
            expected_channel=args.channel,
        )
    except Exception as exc:
        sys.stderr.write(f"[PROVENANCE-FAIL] {exc}\n")
        return 1

    sys.stdout.write(
        f"[PROVENANCE-OK] sha256:{summary['digest']} verified via {summary['workflow_uri']} "
        f"(Rekor t={summary['integrated_time']})\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
