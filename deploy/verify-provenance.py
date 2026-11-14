#!/usr/bin/env python3
"""Cryptographic Sigstore + SLSA v1 provenance verifier for AetherFlow v4 releases.

Zero external PyPI dependencies: uses only Python 3 stdlib + OpenSSL CLI against
pinned Sigstore Public Good Fulcio Root/Intermediate CAs and Rekor Transparency Log
public keys.
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
import urllib.request

SAFE_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SAFE_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Pinned Sigstore Public Good Fulcio Root & Intermediate CAs (from sigstore/root-signing trusted_root.json)
SIGSTORE_FULCIO_ROOTS_B64 = (
    "MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==",
    "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ",
)

SIGSTORE_FULCIO_INTERMEDIATES_B64 = (
    "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow=",
)

# Pinned Sigstore Public Good Rekor Transparency Log public keys (keyId -> (spki_b64, key_type))
SIGSTORE_REKOR_KEYS = {
    "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=": (
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==",
        "PKIX_ECDSA_P256_SHA_256",
    ),
    "tUgTy2PYhZhwpeeFAMxq3P31lyPtrpPujSX68kdaBpA=": (
        "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=",
        "PKIX_ED25519",
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


def _fetch_attestations(api_base_url: str, repo: str, digest: str) -> list[dict]:
    url = f"{api_base_url.rstrip('/')}/repos/{repo}/attestations/sha256:{digest}?per_page=30"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "AetherFlow-ProvenanceVerifier/4.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = _resolve_github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    last_exc: Exception | None = None
    for attempt in range(3):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
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
    # OpenSSL x509 -dates format: "Nov 11 04:47:11 2026 GMT"
    parsed = email.utils.parsedate_tz(raw.strip())
    if parsed is not None:
        return int(email.utils.mktime_tz(parsed))
    dt = time.strptime(raw.strip(), "%b %d %H:%M:%S %Y %Z")
    return int(calendar.timegm(dt))


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


def _extract_der_from_verifier(raw_verifier_b64: str) -> bytes:
    decoded = base64.b64decode(raw_verifier_b64)
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


def _verify_rekor_tlog_entry(
    td: Path,
    tlog: dict,
    expected_payload_sha256: str,
    expected_dsse_sig_b64: str,
    expected_leaf_der: bytes,
) -> int:
    log_id_obj = tlog.get("logId")
    if not isinstance(log_id_obj, dict) or not isinstance(log_id_obj.get("keyId"), str):
        raise ProvenanceVerificationError("missing Rekor logId.keyId")
    key_id = log_id_obj["keyId"]
    if key_id not in SIGSTORE_REKOR_KEYS:
        raise ProvenanceVerificationError(f"untrusted Rekor transparency log keyId: {key_id}")
    spki_b64, key_details = SIGSTORE_REKOR_KEYS[key_id]
    rekor_pub_pem = _wrap_pem("PUBLIC KEY", spki_b64)
    key_id_bytes = base64.b64decode(key_id)

    try:
        integrated_time = int(tlog["integratedTime"])
        log_index = int(tlog["logIndex"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProvenanceVerificationError("missing or invalid Rekor integratedTime/logIndex") from exc
    if integrated_time <= 0 or log_index < 0:
        raise ProvenanceVerificationError("out-of-range Rekor integratedTime/logIndex")

    canon_b64 = tlog.get("canonicalizedBody")
    if not isinstance(canon_b64, str) or not canon_b64:
        raise ProvenanceVerificationError("missing Rekor canonicalizedBody")
    canon_bytes = base64.b64decode(canon_b64)
    try:
        canon_obj = json.loads(canon_bytes.decode("utf-8"))
    except Exception as exc:
        raise ProvenanceVerificationError("invalid JSON in Rekor canonicalizedBody") from exc

    spec = canon_obj.get("spec") if isinstance(canon_obj, dict) else None
    if not isinstance(spec, dict):
        raise ProvenanceVerificationError("missing spec in Rekor canonicalizedBody")

    # Verify Rekor entry binds the exact DSSE payload hash, signature, and leaf X.509 certificate
    payload_hash_obj = spec.get("payloadHash")
    if isinstance(payload_hash_obj, dict):
        alg = str(payload_hash_obj.get("algorithm", "")).lower()
        val = str(payload_hash_obj.get("value", "")).lower()
        if alg != "sha256" or val != expected_payload_sha256:
            raise ProvenanceVerificationError("Rekor payloadHash does not match DSSE payload")
    elif isinstance(spec.get("data"), dict) and isinstance(spec["data"].get("hash"), dict):
        alg = str(spec["data"]["hash"].get("algorithm", "")).lower()
        val = str(spec["data"]["hash"].get("value", "")).lower()
        if alg != "sha256" or val != expected_payload_sha256:
            raise ProvenanceVerificationError("Rekor intoto data.hash does not match DSSE payload")
    else:
        raise ProvenanceVerificationError("Rekor entry lacks payloadHash binding")

    rekor_sigs = spec.get("signatures")
    if not isinstance(rekor_sigs, list) or not rekor_sigs:
        raise ProvenanceVerificationError("Rekor entry lacks signatures binding")

    expected_sig_raw = base64.b64decode(expected_dsse_sig_b64)
    matched_sig_and_cert = False
    for item in rekor_sigs:
        if not isinstance(item, dict):
            continue
        cand = item.get("signature") or item.get("sig")
        ver = item.get("verifier") or item.get("publicKey")
        if not isinstance(cand, str) or not isinstance(ver, str):
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

    # Require cryptographic SET over (body, integratedTime, logID, logIndex) so integratedTime cannot be forged
    promise = tlog.get("inclusionPromise")
    if not isinstance(promise, dict) or not isinstance(promise.get("signedEntryTimestamp"), str):
        raise ProvenanceVerificationError(
            "Rekor tlogEntry missing required inclusionPromise.signedEntryTimestamp"
        )
    set_sig = base64.b64decode(promise["signedEntryTimestamp"])
    set_payload = json.dumps(
        {
            "body": canon_b64,
            "integratedTime": integrated_time,
            "logID": key_id_bytes.hex(),
            "logIndex": log_index,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    _verify_signature_with_openssl(
        td, rekor_pub_pem, key_details, set_payload, set_sig, "rekor-set"
    )

    # Require RFC 6962 Merkle inclusion proof + signed Rekor checkpoint
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
    if int(note_lines[1].strip()) != tree_size:
        raise ProvenanceVerificationError("Rekor checkpoint treeSize mismatch")
    if base64.b64decode(note_lines[2].strip()) != expected_root:
        raise ProvenanceVerificationError("Rekor checkpoint rootHash mismatch")

    checkpoint_verified = False
    for raw_sig_line in sig_section.splitlines():
        line = raw_sig_line.strip()
        if not line:
            continue
        # Checkpoint signature line: "— <origin> <base64(key_hint[4] || sig)>"
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            hint_and_sig = base64.b64decode(parts[-1])
        except Exception:
            continue
        if len(hint_and_sig) <= 4 or hint_and_sig[:4] != key_id_bytes[:4]:
            continue
        _verify_signature_with_openssl(
            td, rekor_pub_pem, key_details, signed_note, hint_and_sig[4:], "rekor-ckpt"
        )
        checkpoint_verified = True
        break
    if not checkpoint_verified:
        raise ProvenanceVerificationError("no valid pinned Rekor signature on checkpoint")

    return integrated_time


def verify_single_bundle(bundle: dict, repo: str, expected_digest: str, artifact_name: str | None) -> dict:
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
    sig_b64 = sigs[0].get("sig") if isinstance(sigs[0], dict) else None
    if not isinstance(sig_b64, str) or not sig_b64:
        raise ProvenanceVerificationError("missing DSSE signature bytes")

    raw_payload = base64.b64decode(payload_b64)
    raw_sig = base64.b64decode(sig_b64)
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

        # 3. Verify Rekor transparency log entry (authenticates integratedTime + binds payload, sig & leaf cert)
        integrated_time: int | None = None
        last_tlog_err: Exception | None = None
        for entry in tlog_entries:
            if not isinstance(entry, dict):
                continue
            try:
                integrated_time = _verify_rekor_tlog_entry(
                    td, entry, payload_sha256, sig_b64, leaf_der
                )
                break
            except Exception as exc:
                last_tlog_err = exc
        if integrated_time is None:
            raise ProvenanceVerificationError(
                f"no valid Rekor transparency log entry: {last_tlog_err}"
            )

        # 4. Verify Fulcio X.509 certificate chain at authenticated integrated_time
        roots_pem = "".join(_wrap_pem("CERTIFICATE", c) for c in SIGSTORE_FULCIO_ROOTS_B64)
        inters_pem = "".join(
            _wrap_pem("CERTIFICATE", c)
            for c in (*SIGSTORE_FULCIO_INTERMEDIATES_B64, *extra_inters_b64)
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
        if not (not_before <= integrated_time <= not_after):
            raise ProvenanceVerificationError(
                f"Rekor integratedTime {integrated_time} outside leaf cert window [{not_before}, {not_after}]"
            )

        chain_res = subprocess.run(
            [
                "openssl",
                "verify",
                "-attime",
                str(integrated_time),
                "-CAfile",
                str(roots_path),
                "-untrusted",
                str(inters_path),
                str(leaf_path),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if chain_res.returncode != 0:
            raise ProvenanceVerificationError(
                f"Fulcio X.509 chain verification failed: {chain_res.stderr.strip() or chain_res.stdout.strip()}"
            )

        # 5. Verify X.509 EKU (Code Signing) + Fulcio GitHub Actions OIDC identity & issuer extensions
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

        # Verify Fulcio OIDC Issuer v1 (1.3.6.1.4.1.57264.1.1) or v2 (1.3.6.1.4.1.57264.1.8)
        issuer_match = re.search(
            r"1\.3\.6\.1\.4\.1\.57264\.1\.(?:1|8):\s*(?:critical\s*)?\n\s*([^\n]+)",
            cert_text,
        )
        if not issuer_match or "https://token.actions.githubusercontent.com" not in issuer_match.group(1):
            raise ProvenanceVerificationError(
                "leaf certificate missing GitHub Actions OIDC issuer extension"
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
        _verify_signature_with_openssl(
            td, pub_res.stdout, "PKIX_ECDSA_P256_SHA_256", pae, raw_sig, "dsse-pae"
        )

    # 7. Verify SLSA v1 in-toto statement & subject binding
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

    return {
        "verified": True,
        "repo": repo,
        "digest": expected_digest,
        "workflow_uri": matched_san,
        "integrated_time": integrated_time,
    }


def verify_provenance(
    repo: str,
    digest: str,
    artifact_name: str | None = None,
    bundle_file: Path | None = None,
    api_base_url: str | None = None,
) -> dict:
    repo = repo.strip()
    if not SAFE_REPO_RE.fullmatch(repo):
        raise ProvenanceVerificationError(f"invalid GitHub repository identifier: {repo!r}")
    digest = digest.strip().lower()
    if not SAFE_HEX64_RE.fullmatch(digest):
        raise ProvenanceVerificationError(f"invalid SHA-256 hex digest: {digest!r}")

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
            return verify_single_bundle(bundle, repo, digest, artifact_name)
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
