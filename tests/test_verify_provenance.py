#!/usr/bin/env python3
"""Deterministic cryptographic unit & tamper tests for deploy/verify-provenance.py.

Exercises both:
1. A real captured GitHub Actions Sigstore Bundle v0.3 from McEveritts/AetherFlow
   (v4.0.0-nightly.109.1 signed by Public Good Fulcio + Rekor v1).
2. Full cryptographic Rekor v2 (`rekor-tiles` / `dsseV002` + Ed25519 C2SP checkpoint +
   RFC 3161 TSA `timestampVerificationData` with `integratedTime == 0` and no SET)
   plus tag/channel/ref/runner_environment/Merkle/signature tamper rejections.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = REPO_ROOT / "deploy" / "verify-provenance.py"

spec = importlib.util.spec_from_file_location("verify_provenance", VERIFIER_PATH)
assert spec is not None and spec.loader is not None
vp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vp)


def _der_from_pem_file(path: Path) -> bytes:
    lines = [
        ln.strip()
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("-----")
    ]
    return base64.b64decode("".join(lines))


def _b64_der_from_pem_file(path: Path) -> str:
    return base64.b64encode(_der_from_pem_file(path)).decode("ascii")


class SyntheticSigstorePKI:
    """Generates an isolated Fulcio + Rekor v1/v2 + RFC 3161 TSA PKI using OpenSSL CLI."""

    def __init__(self, root: Path) -> None:
        self.root = root
        # 1. Fulcio Root CA
        self.fulcio_root_key = root / "fulcio-root.key"
        self.fulcio_root_pem = root / "fulcio-root.pem"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.fulcio_root_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl", "req", "-new", "-x509",
                "-key", str(self.fulcio_root_key),
                "-subj", "/O=sigstore.dev/CN=test-fulcio-root",
                "-days", "365",
                "-out", str(self.fulcio_root_pem),
            ],
            check=True,
            capture_output=True,
        )
        self.fulcio_roots_b64 = (_b64_der_from_pem_file(self.fulcio_root_pem),)

        # 2. Rekor v1 ECDSA P-256 key
        self.rekor_v1_key = root / "rekor-v1.key"
        self.rekor_v1_pub = root / "rekor-v1.pub"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.rekor_v1_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(self.rekor_v1_key), "-pubout", "-out", str(self.rekor_v1_pub)],
            check=True,
            capture_output=True,
        )
        v1_spki = _der_from_pem_file(self.rekor_v1_pub)
        self.rekor_v1_spki_b64 = base64.b64encode(v1_spki).decode("ascii")
        self.rekor_v1_key_id = base64.b64encode(hashlib.sha256(v1_spki).digest()).decode("ascii")

        # 3. Rekor v2 Ed25519 key (C2SP tlog-checkpoint keyId)
        self.rekor_v2_key = root / "rekor-v2.key"
        self.rekor_v2_pub = root / "rekor-v2.pub"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.rekor_v2_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(self.rekor_v2_key), "-pubout", "-out", str(self.rekor_v2_pub)],
            check=True,
            capture_output=True,
        )
        v2_spki = _der_from_pem_file(self.rekor_v2_pub)
        self.rekor_v2_spki_b64 = base64.b64encode(v2_spki).decode("ascii")
        self.rekor_v2_origin = "log2025-1.rekor.sigstore.dev"
        c2sp_id_raw = hashlib.sha256(
            self.rekor_v2_origin.encode("utf-8") + b"\n\x01" + v2_spki[-32:]
        ).digest()
        self.rekor_v2_key_id = base64.b64encode(c2sp_id_raw).decode("ascii")
        self.rekor_v2_hint = c2sp_id_raw[:4]

        self.rekor_keys = {
            self.rekor_v1_key_id: (
                self.rekor_v1_spki_b64,
                "PKIX_ECDSA_P256_SHA_256",
                "rekor.sigstore.dev",
            ),
            self.rekor_v2_key_id: (
                self.rekor_v2_spki_b64,
                "PKIX_ED25519",
                self.rekor_v2_origin,
            ),
        }

        # 4. RFC 3161 TSA Root + Leaf
        self.tsa_root_key = root / "tsa-root.key"
        self.tsa_root_pem = root / "tsa-root.pem"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.tsa_root_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl", "req", "-new", "-x509",
                "-key", str(self.tsa_root_key),
                "-subj", "/O=sigstore.dev/CN=sigstore-tsa-selfsigned",
                "-days", "365",
                "-out", str(self.tsa_root_pem),
            ],
            check=True,
            capture_output=True,
        )
        self.tsa_leaf_key = root / "tsa-leaf.key"
        self.tsa_leaf_pem = root / "tsa-leaf.pem"
        tsa_csr = root / "tsa-leaf.csr"
        tsa_ext = root / "tsa-leaf.ext"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.tsa_leaf_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "req", "-new", "-key", str(self.tsa_leaf_key), "-subj", "/O=sigstore.dev/CN=sigstore-tsa", "-out", str(tsa_csr)],
            check=True,
            capture_output=True,
        )
        tsa_ext.write_text(
            "basicConstraints=CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=critical,timeStamping\n",
            encoding="utf-8",
        )
        subprocess.run(
            [
                "openssl", "x509", "-req",
                "-in", str(tsa_csr),
                "-CA", str(self.tsa_root_pem),
                "-CAkey", str(self.tsa_root_key),
                "-CAcreateserial",
                "-days", "365",
                "-extfile", str(tsa_ext),
                "-out", str(self.tsa_leaf_pem),
            ],
            check=True,
            capture_output=True,
        )
        self.tsa_roots_b64 = (_b64_der_from_pem_file(self.tsa_root_pem),)
        self.tsa_leaves_b64 = (_b64_der_from_pem_file(self.tsa_leaf_pem),)
        self._serial = 1

    def build_bundle(
        self,
        *,
        repo: str = "McEveritts/AetherFlow",
        digest: str = "a" * 64,
        artifact_name: str = "aetherflow-linux-amd64.tar.gz",
        san_ref: str = "refs/tags/v4.0.0",
        slsa_ref: str | None = None,
        runner_env: str = "github-hosted",
        use_rekor_v2: bool = True,
        include_tsa: bool = True,
    ) -> dict:
        idx = self._serial
        self._serial += 1
        if slsa_ref is None:
            slsa_ref = san_ref

        leaf_key = self.root / f"leaf-{idx}.key"
        leaf_csr = self.root / f"leaf-{idx}.csr"
        leaf_ext = self.root / f"leaf-{idx}.ext"
        leaf_pem = self.root / f"leaf-{idx}.pem"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(leaf_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "req", "-new", "-key", str(leaf_key), "-subj", "/", "-out", str(leaf_csr)],
            check=True,
            capture_output=True,
        )
        runner_utf8_hex = (b"\x0c" + bytes([len(runner_env)]) + runner_env.encode("utf-8")).hex().upper()
        issuer_utf8_hex = (
            b"\x0c"
            + bytes([len("https://token.actions.githubusercontent.com")])
            + b"https://token.actions.githubusercontent.com"
        ).hex().upper()
        san_uri = f"https://github.com/{repo}/.github/workflows/release.yml@{san_ref}"
        leaf_ext.write_text(
            "basicConstraints=CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=codeSigning\n"
            f"subjectAltName=critical,URI:{san_uri}\n"
            f"1.3.6.1.4.1.57264.1.8=DER:{issuer_utf8_hex}\n"
            f"1.3.6.1.4.1.57264.1.11=DER:{runner_utf8_hex}\n",
            encoding="utf-8",
        )
        subprocess.run(
            [
                "openssl", "x509", "-req",
                "-in", str(leaf_csr),
                "-CA", str(self.fulcio_root_pem),
                "-CAkey", str(self.fulcio_root_key),
                "-CAcreateserial",
                "-days", "1",
                "-extfile", str(leaf_ext),
                "-out", str(leaf_pem),
            ],
            check=True,
            capture_output=True,
        )
        leaf_b64 = _b64_der_from_pem_file(leaf_pem)

        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": artifact_name, "digest": {"sha256": digest}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                    "externalParameters": {
                        "workflow": {
                            "ref": slsa_ref,
                            "repository": f"https://github.com/{repo}",
                            "path": ".github/workflows/release.yml",
                        }
                    },
                }
            },
        }
        raw_payload = json.dumps(statement, separators=(",", ":")).encode("utf-8")
        payload_b64 = base64.b64encode(raw_payload).decode("ascii")
        payload_type = "application/vnd.in-toto+json"
        pt_bytes = payload_type.encode("utf-8")
        pae = (
            f"DSSEv1 {len(pt_bytes)} ".encode("ascii")
            + pt_bytes
            + f" {len(raw_payload)} ".encode("ascii")
            + raw_payload
        )
        pae_file = self.root / f"pae-{idx}.bin"
        sig_file = self.root / f"sig-{idx}.bin"
        pae_file.write_bytes(pae)
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(leaf_key), "-out", str(sig_file), str(pae_file)],
            check=True,
            capture_output=True,
        )
        raw_sig = sig_file.read_bytes()
        sig_b64 = base64.b64encode(raw_sig).decode("ascii")

        ts_data: dict = {}
        if include_tsa:
            tsq = self.root / f"ts-{idx}.tsq"
            tsr = self.root / f"ts-{idx}.tsr"
            cnf = self.root / f"tsa-{idx}.cnf"
            ser = self.root / f"tsaserial-{idx}"
            ser.write_text(f"{idx:04x}\n", encoding="utf-8")
            cnf.write_text(
                f"[tsa]\ndefault_tsa = tsa_cfg\n[tsa_cfg]\nserial = {ser}\ndigests = sha256\ndefault_policy = 1.2.3.4.1\nsigner_digest = sha256\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["openssl", "ts", "-query", "-data", str(sig_file), "-sha256", "-cert", "-out", str(tsq)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "openssl", "ts", "-reply",
                    "-config", str(cnf),
                    "-queryfile", str(tsq),
                    "-signer", str(self.tsa_leaf_pem),
                    "-inkey", str(self.tsa_leaf_key),
                    "-out", str(tsr),
                ],
                check=True,
                capture_output=True,
            )
            ts_data = {
                "rfc3161Timestamps": [
                    {"signedTimestamp": base64.b64encode(tsr.read_bytes()).decode("ascii")}
                ]
            }

        payload_digest_bytes = hashlib.sha256(raw_payload).digest()
        if use_rekor_v2:
            canon_obj = {
                "apiVersion": "0.0.2",
                "kind": "dsse",
                "spec": {
                    "dsseV002": {
                        "payloadHash": {
                            "algorithm": "SHA2_256",
                            "digest": base64.b64encode(payload_digest_bytes).decode("ascii"),
                        },
                        "signatures": [
                            {
                                "content": sig_b64,
                                "verifier": {
                                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                                    "x509Certificate": {"rawBytes": leaf_b64},
                                },
                            }
                        ],
                    }
                },
            }
            canon_bytes = json.dumps(canon_obj, separators=(",", ":")).encode("utf-8")
            canon_b64 = base64.b64encode(canon_bytes).decode("ascii")
            leaf_hash = hashlib.sha256(b"\x00" + canon_bytes).digest()
            root_hash_b64 = base64.b64encode(leaf_hash).decode("ascii")
            note_body = f"{self.rekor_v2_origin}\n1\n{root_hash_b64}"
            note_file = self.root / f"note-{idx}.bin"
            note_sig = self.root / f"note-{idx}.sig"
            note_file.write_bytes((note_body + "\n").encode("utf-8"))
            subprocess.run(
                [
                    "openssl", "pkeyutl", "-sign",
                    "-inkey", str(self.rekor_v2_key),
                    "-rawin",
                    "-in", str(note_file),
                    "-out", str(note_sig),
                ],
                check=True,
                capture_output=True,
            )
            ckpt_sig_b64 = base64.b64encode(self.rekor_v2_hint + note_sig.read_bytes()).decode("ascii")
            envelope = f"{note_body}\n\n\u2014 {self.rekor_v2_origin} {ckpt_sig_b64}\n"
            tlog_entry = {
                "logIndex": "0",
                "logId": {"keyId": self.rekor_v2_key_id},
                "kindVersion": {"kind": "dsse", "version": "0.0.2"},
                "integratedTime": "0",
                "inclusionProof": {
                    "logIndex": "0",
                    "rootHash": root_hash_b64,
                    "treeSize": "1",
                    "hashes": [],
                    "checkpoint": {"envelope": envelope},
                },
                "canonicalizedBody": canon_b64,
            }
        else:
            now_epoch = int(time.time())
            canon_obj = {
                "apiVersion": "0.0.1",
                "kind": "dsse",
                "spec": {
                    "payloadHash": {"algorithm": "sha256", "value": payload_digest_bytes.hex()},
                    "signatures": [{"signature": sig_b64, "verifier": leaf_b64}],
                },
            }
            canon_bytes = json.dumps(canon_obj, separators=(",", ":")).encode("utf-8")
            canon_b64 = base64.b64encode(canon_bytes).decode("ascii")
            leaf_hash = hashlib.sha256(b"\x00" + canon_bytes).digest()
            root_hash_b64 = base64.b64encode(leaf_hash).decode("ascii")
            note_body = f"rekor.sigstore.dev - 1\n1\n{root_hash_b64}"
            note_file = self.root / f"note-{idx}.bin"
            note_sig = self.root / f"note-{idx}.sig"
            note_file.write_bytes((note_body + "\n").encode("utf-8"))
            subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(self.rekor_v1_key), "-out", str(note_sig), str(note_file)],
                check=True,
                capture_output=True,
            )
            v1_hint = base64.b64decode(self.rekor_v1_key_id)[:4]
            ckpt_sig_b64 = base64.b64encode(v1_hint + note_sig.read_bytes()).decode("ascii")
            envelope = f"{note_body}\n\n\u2014 rekor.sigstore.dev {ckpt_sig_b64}\n"

            set_payload = json.dumps(
                {
                    "body": canon_b64,
                    "integratedTime": now_epoch,
                    "logID": base64.b64decode(self.rekor_v1_key_id).hex(),
                    "logIndex": 0,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            set_file = self.root / f"set-{idx}.bin"
            set_sig = self.root / f"set-{idx}.sig"
            set_file.write_bytes(set_payload)
            subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(self.rekor_v1_key), "-out", str(set_sig), str(set_file)],
                check=True,
                capture_output=True,
            )
            tlog_entry = {
                "logIndex": "0",
                "logId": {"keyId": self.rekor_v1_key_id},
                "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                "integratedTime": str(now_epoch),
                "inclusionPromise": {
                    "signedEntryTimestamp": base64.b64encode(set_sig.read_bytes()).decode("ascii")
                },
                "inclusionProof": {
                    "logIndex": "0",
                    "rootHash": root_hash_b64,
                    "treeSize": "1",
                    "hashes": [],
                    "checkpoint": {"envelope": envelope},
                },
                "canonicalizedBody": canon_b64,
            }

        return {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": {"rawBytes": leaf_b64},
                "tlogEntries": [tlog_entry],
                "timestampVerificationData": ts_data,
            },
            "dsseEnvelope": {
                "payload": payload_b64,
                "payloadType": payload_type,
                "signatures": [{"sig": sig_b64, "keyid": ""}],
            },
        }


class VerifyProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="af-prov-pki-")
        cls.pki = SyntheticSigstorePKI(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _verify(self, bundle: dict, **kwargs) -> dict:
        return vp.verify_single_bundle(
            bundle,
            fulcio_roots_b64=self.pki.fulcio_roots_b64,
            fulcio_intermediates_b64=(),
            rekor_keys=self.pki.rekor_keys,
            tsa_roots_b64=self.pki.tsa_roots_b64,
            tsa_leaves_b64=self.pki.tsa_leaves_b64,
            **kwargs,
        )

    def test_rekor_v2_dssev002_with_ed25519_checkpoint_and_rfc3161_tsa_succeeds(self) -> None:
        digest = "12" * 32
        bundle = self.pki.build_bundle(
            digest=digest,
            san_ref="refs/tags/v4.0.0",
            use_rekor_v2=True,
            include_tsa=True,
        )
        res = self._verify(
            bundle,
            repo="McEveritts/AetherFlow",
            expected_digest=digest,
            artifact_name="aetherflow-linux-amd64.tar.gz",
            expected_tag="v4.0.0",
            expected_channel="stable",
        )
        self.assertTrue(res["verified"])
        self.assertEqual(res["workflow_ref"], "refs/tags/v4.0.0")

    def test_rekor_v1_with_ecdsa_set_and_nightly_ref_succeeds(self) -> None:
        digest = "34" * 32
        bundle = self.pki.build_bundle(
            digest=digest,
            san_ref="refs/heads/nightly",
            use_rekor_v2=False,
            include_tsa=False,
        )
        res = self._verify(
            bundle,
            repo="McEveritts/AetherFlow",
            expected_digest=digest,
            artifact_name="aetherflow-linux-amd64.tar.gz",
            expected_tag="v4.0.0-nightly.110.1",
            expected_channel="nightly",
        )
        self.assertTrue(res["verified"])
        self.assertEqual(res["workflow_ref"], "refs/heads/nightly")

    def test_rekor_v2_without_tsa_or_set_fails_closed(self) -> None:
        digest = "56" * 32
        bundle = self.pki.build_bundle(
            digest=digest,
            san_ref="refs/tags/v4.0.0",
            use_rekor_v2=True,
            include_tsa=False,
        )
        with self.assertRaisesRegex(vp.ProvenanceVerificationError, "lacks authenticated signing timestamp"):
            self._verify(
                bundle,
                repo="McEveritts/AetherFlow",
                expected_digest=digest,
                artifact_name="aetherflow-linux-amd64.tar.gz",
                expected_tag="v4.0.0",
                expected_channel="stable",
            )

    def test_cross_channel_nightly_bundle_replayed_as_stable_fails_closed(self) -> None:
        digest = "78" * 32
        bundle = self.pki.build_bundle(
            digest=digest,
            san_ref="refs/heads/nightly",
            use_rekor_v2=True,
            include_tsa=True,
        )
        with self.assertRaisesRegex(vp.ProvenanceVerificationError, "requires workflow ref 'refs/tags/v4.0.0'"):
            self._verify(
                bundle,
                repo="McEveritts/AetherFlow",
                expected_digest=digest,
                artifact_name="aetherflow-linux-amd64.tar.gz",
                expected_tag="v4.0.0",
                expected_channel="stable",
            )

    def test_older_stable_tag_replayed_as_newer_stable_tag_fails_closed(self) -> None:
        digest = "9a" * 32
        bundle = self.pki.build_bundle(
            digest=digest,
            san_ref="refs/tags/v4.0.0",
            use_rekor_v2=True,
            include_tsa=True,
        )
        with self.assertRaisesRegex(vp.ProvenanceVerificationError, "requires workflow ref 'refs/tags/v4.0.1'"):
            self._verify(
                bundle,
                repo="McEveritts/AetherFlow",
                expected_digest=digest,
                artifact_name="aetherflow-linux-amd64.tar.gz",
                expected_tag="v4.0.1",
                expected_channel="stable",
            )

    def test_unprotected_feature_branch_workflow_dispatch_fails_closed(self) -> None:
        digest = "bc" * 32
        bundle = self.pki.build_bundle(
            digest=digest,
            san_ref="refs/heads/feature-malicious-dispatch",
            use_rekor_v2=True,
            include_tsa=True,
        )
        with self.assertRaisesRegex(vp.ProvenanceVerificationError, "not a protected nightly branch or v4\\+ release tag"):
            self._verify(
                bundle,
                repo="McEveritts/AetherFlow",
                expected_digest=digest,
                artifact_name="aetherflow-linux-amd64.tar.gz",
            )

    def test_self_hosted_runner_environment_fails_closed(self) -> None:
        digest = "de" * 32
        bundle = self.pki.build_bundle(
            digest=digest,
            san_ref="refs/tags/v4.0.0",
            runner_env="self-hosted",
            use_rekor_v2=True,
            include_tsa=True,
        )
        with self.assertRaisesRegex(vp.ProvenanceVerificationError, "runner_environment"):
            self._verify(
                bundle,
                repo="McEveritts/AetherFlow",
                expected_digest=digest,
                artifact_name="aetherflow-linux-amd64.tar.gz",
                expected_tag="v4.0.0",
                expected_channel="stable",
            )

    def test_tampered_tsa_signature_or_dsse_payload_fails_closed(self) -> None:
        digest = "f0" * 32
        bundle = self.pki.build_bundle(
            digest=digest,
            san_ref="refs/tags/v4.0.0",
            use_rekor_v2=True,
            include_tsa=True,
        )
        tampered = copy.deepcopy(bundle)
        raw_ts = bytearray(
            base64.b64decode(
                tampered["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0]["signedTimestamp"]
            )
        )
        raw_ts[-1] ^= 0xFF
        tampered["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0]["signedTimestamp"] = (
            base64.b64encode(bytes(raw_ts)).decode("ascii")
        )
        with self.assertRaisesRegex(vp.ProvenanceVerificationError, "RFC 3161 TSA verification failed"):
            self._verify(
                tampered,
                repo="McEveritts/AetherFlow",
                expected_digest=digest,
                artifact_name="aetherflow-linux-amd64.tar.gz",
                expected_tag="v4.0.0",
                expected_channel="stable",
            )

    def test_real_github_actions_sigstore_bundle_nightly_109_1_verifies_end_to_end(self) -> None:
        fixture = REPO_ROOT / "tests" / "fixtures" / "sigstore_bundle_nightly_109_1.json"
        digest = "018a270e2833886b1c59e2f831912c794e2ed66dacf6c2249ab1390fc2d44b26"
        res = vp.verify_provenance(
            repo="McEveritts/AetherFlow",
            digest=digest,
            artifact_name="aetherflow-linux-amd64.tar.gz",
            bundle_file=fixture,
            expected_tag="v4.0.0-nightly.109.1",
            expected_channel="nightly",
        )
        self.assertTrue(res["verified"])
        self.assertEqual(res["workflow_ref"], "refs/heads/nightly")
        with self.assertRaisesRegex(vp.ProvenanceVerificationError, "requires workflow ref 'refs/tags/v4.0.0'"):
            vp.verify_provenance(
                repo="McEveritts/AetherFlow",
                digest=digest,
                artifact_name="aetherflow-linux-amd64.tar.gz",
                bundle_file=fixture,
                expected_tag="v4.0.0",
                expected_channel="stable",
            )


if __name__ == "__main__":
    unittest.main()
