#!/usr/bin/env python3
"""Content-address Trunk's stable worker names before publishing immutable assets.

Runs as a Trunk post_build hook, including direct `trunk build --release` calls.
No application logic is implemented in JavaScript; these files are bindgen glue.
"""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from html import escape
from html.parser import HTMLParser

CATALOG_DIR = Path(__file__).resolve().parents[1] / "frontend-rs/crates/af-web-core/catalogs"
LAZY_LOCALES = ("de", "dk", "es", "fr", "zh")


def read_wasm_u32(data: bytes, offset: int, end: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 35, 7):
        if offset >= end:
            raise ValueError("Truncated WASM section length")
        byte = data[offset]
        offset += 1
        if shift == 28 and byte & 0xF0:
            raise ValueError("WASM section length exceeds u32")
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
    raise ValueError("Invalid WASM section length")


def strip_wasm_custom_sections(data: bytes) -> bytes:
    """Drop development metadata while preserving executable and runtime sections."""
    if data[:8] != b"\x00asm\x01\x00\x00\x00":
        raise ValueError("Invalid WASM module header")
    output = bytearray(data[:8])
    offset = 8
    while offset < len(data):
        start = offset
        section_id = data[offset]
        size, payload = read_wasm_u32(data, offset + 1, len(data))
        end = payload + size
        if end > len(data):
            raise ValueError("Truncated WASM section payload")
        discard = False
        if section_id == 0:
            name_size, name_start = read_wasm_u32(data, payload, end)
            if name_start + name_size > end:
                raise ValueError("Truncated WASM custom section name")
            name = data[name_start:name_start + name_size].decode("utf-8")
            discard = name in {"name", "producers", "target_features"} or name.startswith(".debug")
        if not discard:
            output.extend(data[start:end])
        offset = end
    return bytes(output)


def rewrite_references(text: str, replacements: dict[str, str]) -> str:
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def record_asset_change(dist: Path, path: Path, data: bytes, replacements: dict[str, str], *, rename=True):
    original = path.read_bytes()
    destination = path
    if rename:
        stem = re.sub(r"-[0-9a-f]{16,64}(?=(?:_bg)?$)", "", path.stem)
        digest = hashlib.sha256(data).hexdigest()[:16]
        destination = path.with_name(f"{stem}-{digest}{path.suffix}")
        replacements[path.relative_to(dist).as_posix()] = destination.relative_to(dist).as_posix()
    for algorithm in ("sha256", "sha384", "sha512"):
        before = base64.b64encode(hashlib.new(algorithm, original).digest()).decode("ascii")
        after = base64.b64encode(hashlib.new(algorithm, data).digest()).decode("ascii")
        if before != after:
            replacements[f"{algorithm}-{before}"] = f"{algorithm}-{after}"
    destination.write_bytes(data)
    if destination != path:
        path.unlink()
    # Sidecars from Trunk describe the original bytes and must be regenerated.
    for asset in {path, destination}:
        for extension in ("gz", "br"):
            asset.with_name(f"{asset.name}.{extension}").unlink(missing_ok=True)


def compress_brotli(data: bytes) -> bytes:
    """Use the Python module or the system encoder, without a pip build step."""
    try:
        import brotli
    except ImportError:
        import ctypes
        import ctypes.util

        library = ctypes.util.find_library("brotlienc")
        if not library:
            raise RuntimeError("Locale assets require the brotli module or libbrotlienc")
        encoder = ctypes.CDLL(library)
        encoder.BrotliEncoderMaxCompressedSize.argtypes = [ctypes.c_size_t]
        encoder.BrotliEncoderMaxCompressedSize.restype = ctypes.c_size_t
        encoder.BrotliEncoderCompress.argtypes = [
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p,
        ]
        encoder.BrotliEncoderCompress.restype = ctypes.c_int
        size = ctypes.c_size_t(encoder.BrotliEncoderMaxCompressedSize(len(data)))
        output = ctypes.create_string_buffer(size.value)
        if not encoder.BrotliEncoderCompress(11, 22, 0, len(data), data, ctypes.byref(size), output):
            raise RuntimeError("Brotli compression of locale assets failed")
        return output.raw[:size.value]
    else:
        return brotli.compress(data, quality=11, lgwin=22)


def write_smaller_sidecar(path: Path, extension: str, compressed: bytes, raw_size: int):
    sidecar = path.with_name(f"{path.name}.{extension}")
    if len(compressed) < raw_size:
        sidecar.write_bytes(compressed)
    else:
        sidecar.unlink(missing_ok=True)


def publish_locales(dist: Path):
    directory = dist / "locales"
    directory.mkdir(parents=True, exist_ok=True)
    for locale in LAZY_LOCALES:
        catalog = json.loads((CATALOG_DIR / f"{locale}.json").read_text(encoding="utf-8"))
        data = json.dumps(catalog, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        path = directory / f"{locale}.json"
        path.write_bytes(data)
        gz = gzip.compress(data, compresslevel=9, mtime=0)
        br = compress_brotli(data)
        write_smaller_sidecar(path, "gz", gz, len(data))
        write_smaller_sidecar(path, "br", br, len(data))


def audit_rsx_output(dist: Path):
    for path in sorted(dist.rglob("*")):
        if not path.is_file() or path.suffix not in {".wasm", ".html"}:
            continue
        wasm_bytes = path.read_bytes()
        if re.search(rb"on\s*:\s*(?:click|input|change|keydown|submit)\s*=\s*move\s*\|", wasm_bytes) or any(
            leaked in wasm_bytes for leaked in (b"on:click=move", b"on:input=move", b"= 24\n", b"= 24\r\n")
        ):
            raise ValueError(f"Leaked RSX closure text in generated artifact: {path}")


class ScriptAudit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inline_scripts = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script" and not dict(attrs).get("src"):
            self.inline_scripts += 1


class LinkAttributes(HTMLParser):
    def __init__(self):
        super().__init__()
        self.attributes = {}

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "link":
            self.attributes = dict(attrs)


def anonymous_stylesheet(match):
    tag = match.group(0)
    parser = LinkAttributes()
    parser.feed(tag)
    attrs = parser.attributes
    if ("stylesheet" not in (attrs.get("rel") or "").lower().split()
            or not any(value.startswith("sha384-") for value in (attrs.get("integrity") or "").split())):
        return tag
    if attrs.get("crossorigin") == "anonymous":
        return tag
    tag = re.sub(r'''\s+crossorigin(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?''',
                 "", tag, flags=re.IGNORECASE)
    ending = "/>" if tag.endswith("/>") else ">"
    return f'{tag[:-len(ending)].rstrip()} crossorigin="anonymous"{ending}'


def supported_preload_integrity(match):
    tag = match.group(0)
    parser = LinkAttributes()
    parser.feed(tag)
    attrs = parser.attributes
    # Chromium cannot enforce SRI on a fetch preload and warns if it is present.
    # Retain enforced integrity on module preloads, scripts, and stylesheets.
    if ("preload" in (attrs.get("rel") or "").lower().split()
            and (attrs.get("as") or "").lower() == "fetch"):
        return re.sub(r'''\s+integrity\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)''',
                      "", tag, flags=re.IGNORECASE)
    return tag


def finalize(dist: Path):
    # Check before renaming/compressing so malformed RSX fails closed even when
    # Rust compiled it as a visible text node instead of a button attribute.
    audit_rsx_output(dist)
    publish_locales(dist)
    replacements = {}
    for path in sorted(dist.rglob("*.wasm")):
        original = path.read_bytes()
        data = strip_wasm_custom_sections(original)
        if data != original:
            record_asset_change(dist, path, data, replacements, rename=path.name != "af-web-worker_bg.wasm")
    # Rename leaves before their importers so all embedded URLs match their bytes.
    names = ["af-web-worker_bg.wasm", "af-web-worker.js", "af-web-worker_loader.js"]
    worker_artifacts = set()
    for name in names:
        path = dist / name
        if not path.is_file():
            raise SystemExit(f"Missing Trunk worker artifact: {path}")
        data = path.read_bytes()
        if path.suffix == ".js":
            data = rewrite_references(data.decode("utf-8"), replacements).encode("utf-8")
        record_asset_change(dist, path, data, replacements)
        worker_artifacts.add(dist / replacements[name])
    # Resolve module dependencies before their importers, including external
    # bootstraps whose filenames sort before the application bindgen glue.
    modules = {
        path: path.read_text(encoding="utf-8") for path in sorted(dist.rglob("*.js"))
        if path not in worker_artifacts and path.name != "sw.js"
    }
    completed, visiting = set(), set()

    def finalize_module(path):
        if path in completed:
            return
        if path in visiting:
            raise ValueError("Cyclic generated JavaScript asset dependencies")
        visiting.add(path)
        original = modules[path]
        for dependency in modules:
            if dependency != path and dependency.relative_to(dist).as_posix() in original:
                finalize_module(dependency)
        data = rewrite_references(original, replacements).encode("utf-8")
        if data != original.encode("utf-8"):
            record_asset_change(dist, path, data, replacements)
        visiting.remove(path)
        completed.add(path)

    for path in modules:
        finalize_module(path)
    index = dist / "index.html"
    text = rewrite_references(index.read_text(encoding="utf-8"), replacements)
    # Trunk 0.22 emits both a fetch preload and a bindgen fetch for the app.
    # WebKit can transfer both, so start one explicit fetch concurrently with
    # the module import instead. The pinned bindgen initializer accepts a
    # Response in module_or_path and retains its streaming/fallback handling.
    wasm_preloads = []
    for link in re.finditer(r"<link\b[^>]*>", text, re.IGNORECASE):
        parser = LinkAttributes()
        parser.feed(link.group())
        attrs = parser.attributes
        href = attrs.get("href") or ""
        if ("preload" in (attrs.get("rel") or "").lower().split()
                and (attrs.get("as") or "").lower() == "fetch" and href.endswith(".wasm")):
            wasm_preloads.append(href)
    app_wasm = []

    def externalize(match):
        attrs = match.group(1)
        audit = ScriptAudit()
        audit.feed(f"<script {attrs}></script>")
        if not audit.inline_scripts:
            return match.group(0)
        if not re.search(r"\btype\s*=\s*(['\"])module\1", attrs, re.IGNORECASE):
            raise ValueError("Unexpected inline script: only Trunk module bootstraps are supported")
        bootstrap = re.sub(r"\bwindow\.wasmBindings\s*=\s*bindings\s*;?", "", match.group(2))
        imported = re.search(
            r'''(?m)^\s*import\s+init(?:\s*,\s*\*\s+as\s+bindings)?\s+from\s+(["'])([^"']+\.js)\1\s*;''',
            bootstrap,
        )
        initializer = re.search(
            r'''(\bconst\s+wasm\s*=\s*await\s+init\s*\(\s*\{\s*module_or_path\s*:\s*)(["'])([^"']+\.wasm)\2(\s*\}\s*\)\s*;)''',
            bootstrap,
        )
        if initializer:
            wasm_url = initializer.group(3)
            if (not imported or imported.end() > initializer.start()
                    or wasm_preloads.count(wasm_url) != 1 or app_wasm):
                raise ValueError("Expected one Trunk application module and matching WASM preload")
            if not re.fullmatch(r"/?[A-Za-z0-9_./-]+\.wasm", wasm_url):
                raise ValueError(f"Invalid application WASM URL: {wasm_url}")
            wasm_path = (dist / wasm_url.lstrip("/")).resolve(strict=True)
            if not wasm_path.is_relative_to(dist.resolve()) or not wasm_path.is_file():
                raise ValueError(f"Application WASM is outside the build directory: {wasm_url}")
            integrity = base64.b64encode(hashlib.sha384(wasm_path.read_bytes()).digest()).decode("ascii")
            app_wasm.append(wasm_url)
            bootstrap = (bootstrap[:initializer.start()] + initializer.group(1) + "wasmResponse"
                         + initializer.group(4) + bootstrap[initializer.end():])
            replacement = (
                "\nconst [wasmResponse, { default: init }] = await Promise.all([\n"
                f"    fetch({json.dumps(wasm_url)}, {{ integrity: {json.dumps('sha384-' + integrity)} }}),\n"
                f"    import({json.dumps(imported.group(2))})\n"
                "]);"
            )
            bootstrap = bootstrap[:imported.start()] + replacement + bootstrap[imported.end():]
        data = bootstrap.encode("utf-8")
        name = f"af-bootstrap-{hashlib.sha256(data).hexdigest()[:16]}.js"
        (dist / name).write_bytes(data)
        integrity = base64.b64encode(hashlib.sha384(data).digest()).decode("ascii")
        return (f'<script type="module" src="/{name}" integrity="sha384-{integrity}" '
                'crossorigin="anonymous"></script>')

    text = re.sub(r"<script\b([^>]*)>(.*?)</script\s*>", externalize, text,
                  flags=re.IGNORECASE | re.DOTALL)
    if wasm_preloads != app_wasm:
        raise ValueError("Unmatched application WASM fetch preload in Trunk output")
    def replace_app_preload(match):
        parser = LinkAttributes()
        parser.feed(match.group())
        attrs = parser.attributes
        if (app_wasm and attrs.get("href") == app_wasm[0]
                and "preload" in (attrs.get("rel") or "").lower().split()
                and (attrs.get("as") or "").lower() == "fetch"):
            return f'<meta name="af-app-wasm-url" content="{escape(app_wasm[0], quote=True)}">'
        return match.group()

    text = re.sub(r"<link\b[^>]*>", replace_app_preload, text, flags=re.IGNORECASE)
    text = re.sub(r"<link\b[^>]*>", anonymous_stylesheet, text, flags=re.IGNORECASE)
    text = re.sub(r"<link\b[^>]*>", supported_preload_integrity, text, flags=re.IGNORECASE)
    audit = ScriptAudit()
    audit.feed(text)
    if audit.inline_scripts:
        raise ValueError("Inline script blocks remain in the finalized index.html")
    index.write_text(text, encoding="utf-8")
    # Tie the cache namespace to the final document, including rewritten worker
    # URLs and the external bootstrap, rather than a manually bumped version.
    service_worker = dist / "sw.js"
    if service_worker.is_file():
        build_hash = hashlib.sha256(index.read_bytes()).hexdigest()[:16]
        service_worker.write_text(
            rewrite_references(service_worker.read_text(encoding="utf-8"), replacements).replace("__BUILD_HASH__", build_hash),
            encoding="utf-8",
        )
    # Trunk's lock/staging metadata must never become an immutable public asset.
    for path in sorted(dist.rglob(".trunk*"), key=lambda p: len(p.parts), reverse=True):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    # Browsers on cleartext LAN HTTP may advertise gzip without Brotli. Write
    # sidecars only after every content-addressed URL and service worker changed.
    for path in sorted(dist.rglob("*")):
        if (not path.is_file() or path.relative_to(dist).parts[0] == "locales"
                or path.suffix not in {".wasm", ".js", ".css", ".json", ".svg"}):
            continue
        raw = path.read_bytes()
        write_smaller_sidecar(path, "gz", gzip.compress(raw, compresslevel=9, mtime=0), len(raw))
        if path.suffix in {".json", ".svg"}:
            write_smaller_sidecar(path, "br", compress_brotli(raw), len(raw))
        else:
            # Rust's compressor writes these Brotli sidecars. Discard any old
            # oversized sidecar without recompressing the same asset here.
            sidecar = path.with_name(path.name + ".br")
            if sidecar.is_file() and sidecar.stat().st_size >= len(raw):
                sidecar.unlink()


def self_test():
    import subprocess
    import tempfile
    import unittest
    from unittest.mock import patch

    # A small executable module exporting answer() -> 42.
    executable = bytes.fromhex("0061736d010000000105016000017f03020100070a0106616e7377657200000a06010400412a0b")

    def u32(value):
        encoded = bytearray()
        while value >= 128:
            encoded.append((value & 127) | 128)
            value >>= 7
        encoded.append(value)
        return bytes(encoded)

    def custom(name, payload=b""):
        name = name.encode("utf-8")
        data = u32(len(name)) + name + payload
        return b"\x00" + u32(len(data)) + data

    class FinalizerTests(unittest.TestCase):
        def test_metadata_stripping_preserves_valid_executable_and_runtime_sections(self):
            runtime = custom("dylink.0", b"\x00" * 256)
            metadata = b"".join(custom(name) for name in ["name", "producers", "target_features", ".debug_info", ".debug_line"])
            original = executable + metadata + runtime
            stripped = strip_wasm_custom_sections(original)
            self.assertEqual(stripped, executable + runtime)
            self.assertEqual(strip_wasm_custom_sections(stripped), stripped)
            self.assertEqual(strip_wasm_custom_sections(executable + metadata), executable)
            with tempfile.TemporaryDirectory() as tmp:
                module = Path(tmp) / "module.wasm"
                module.write_bytes(stripped)
                if shutil.which("node"):
                    subprocess.run([
                        "node", "-e",
                        "const fs = require('node:fs'); const bytes = fs.readFileSync(process.argv[1]); "
                        "if (!WebAssembly.validate(bytes)) process.exit(1); "
                        "const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes)); "
                        "if (instance.exports.answer() !== 42) process.exit(2);",
                        str(module),
                    ], check=True, capture_output=True)
                elif shutil.which("wasm-opt"):
                    subprocess.run(["wasm-opt", str(module), "--all-features", "-o", str(Path(tmp) / "validated.wasm")],
                                   check=True, capture_output=True)

        def test_malformed_wasm_metadata_is_rejected(self):
            for data in [b"", b"\x00asm-test", executable + b"\x00\x80", executable + b"\x00\x05\x00",
                         executable + b"\x00\x01\x02", executable + b"\x00\x80\x80\x80\x80\x10"]:
                with self.subTest(data=data), self.assertRaises(ValueError):
                    strip_wasm_custom_sections(data)

        def test_fetch_preload_sri_policy_leaves_enforced_module_integrity(self):
            fetch = '<link rel="preload" as="fetch" href="/data.json" integrity="sha384-value">'
            module = '<link rel="modulepreload" href="/app.js" integrity="sha384-value">'
            self.assertEqual(supported_preload_integrity(re.match(r".*", fetch)),
                             '<link rel="preload" as="fetch" href="/data.json">')
            self.assertEqual(supported_preload_integrity(re.match(r".*", module)), module)

        def test_stripped_application_wasm_rehashes_glue_bootstrap_and_sri(self):
            with tempfile.TemporaryDirectory() as tmp:
                dist = Path(tmp)
                original = executable + custom("name", b"debug symbols") + custom("producers") + custom("target_features")
                old_wasm = "app-0123456789abcdef_bg.wasm"
                old_glue = "app-0123456789abcdef.js"
                old_launcher = "a-launcher-0123456789abcdef.js"
                (dist / old_wasm).write_bytes(original)
                glue_data = f"export default () => fetch('/{old_wasm}');".encode()
                (dist / old_glue).write_bytes(glue_data)
                (dist / old_launcher).write_text(f'export {{ default }} from "/{old_glue}";')
                original_sri = base64.b64encode(hashlib.sha384(original).digest()).decode("ascii")
                glue_sri = base64.b64encode(hashlib.sha384(glue_data).digest()).decode("ascii")
                for name in [old_wasm, old_glue]:
                    (dist / f"{name}.gz").write_bytes(b"stale")
                    (dist / f"{name}.br").write_bytes(b"stale")
                (dist / "af-web-worker_bg.wasm").write_bytes(original)
                (dist / "af-web-worker.js").write_text("fetch('af-web-worker_bg.wasm');")
                (dist / "af-web-worker_loader.js").write_text("import './af-web-worker.js';")
                (dist / "index.html").write_text(
                    f'<link rel="preload" href="/{old_wasm}" as="fetch" type="application/wasm" integrity="sha384-{original_sri}">'
                    f'<link rel="modulepreload" href="/{old_glue}" integrity="sha384-{glue_sri}">'
                    f'<script type="module">\nimport init from "/{old_launcher}";\n'
                    f'const wasm = await init({{ module_or_path: "/{old_wasm}" }});\n'
                    'dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));</script>')
                finalize(dist)
                wasm, = dist.glob("app_bg-*.wasm")
                glue, = dist.glob("app-*.js")
                self.assertEqual(wasm.read_bytes(), executable)
                self.assertIn(hashlib.sha256(executable).hexdigest()[:16], wasm.name)
                self.assertIn(wasm.name, glue.read_text())
                self.assertIn(hashlib.sha256(glue.read_bytes()).hexdigest()[:16], glue.name)
                html = (dist / "index.html").read_text()
                self.assertIn(wasm.name, html)
                self.assertIn(glue.name, html)
                self.assertIn(f'<meta name="af-app-wasm-url" content="/{wasm.name}">', html)
                self.assertNotIn('rel="preload"', html)
                for asset in [wasm, glue]:
                    sri = base64.b64encode(hashlib.sha384(asset.read_bytes()).digest()).decode("ascii")
                    if asset == wasm:
                        self.assertNotIn(f'integrity="sha384-{sri}"', html)
                    else:
                        self.assertIn(f'integrity="sha384-{sri}"', html)
                    self.assertFalse(asset.with_name(asset.name + ".br").exists())
                for old in [old_wasm, old_glue]:
                    self.assertFalse((dist / old).exists())
                    self.assertFalse((dist / f"{old}.gz").exists())
                    self.assertFalse((dist / f"{old}.br").exists())
                bootstrap, = dist.glob("af-bootstrap-*.js")
                launcher, = dist.glob("a-launcher-*.js")
                self.assertIn(launcher.name, bootstrap.read_text())
                self.assertIn(glue.name, launcher.read_text())
                self.assertIn(f'fetch("/{wasm.name}", {{ integrity: "sha384-', bootstrap.read_text())
                self.assertIn(f'sha384-{base64.b64encode(hashlib.sha384(executable).digest()).decode("ascii")}',
                              bootstrap.read_text())
                self.assertIn('module_or_path: wasmResponse', bootstrap.read_text())
                self.assertIn('TrunkApplicationStarted', bootstrap.read_text())
                self.assertIn(hashlib.sha256(launcher.read_bytes()).hexdigest()[:16], launcher.name)
                self.assertNotIn(old_launcher, bootstrap.read_text())
                self.assertNotIn(old_glue, launcher.read_text())

        def test_single_fetch_finalization_is_deterministic_and_cache_stamped(self):
            with tempfile.TemporaryDirectory() as tmp:
                roots = [Path(tmp) / "first", Path(tmp) / "second"]
                for dist in roots:
                    dist.mkdir()
                    wasm = "af-web-app_bg-0123456789abcdef.wasm"
                    glue = "af-web-app-0123456789abcdef.js"
                    data = executable + custom("name", b"debug")
                    (dist / wasm).write_bytes(data)
                    (dist / glue).write_text(f"export default () => fetch('/{wasm}');\n" + "// glue\n" * 30)
                    (dist / "af-web-worker_bg.wasm").write_bytes(executable)
                    (dist / "af-web-worker.js").write_text("fetch('af-web-worker_bg.wasm');\n" + "// worker\n" * 30)
                    (dist / "af-web-worker_loader.js").write_text("import './af-web-worker.js';\n" + "// loader\n" * 30)
                    (dist / "sw.js").write_text("const CACHE_NAME = 'aetherflow-cache-wasm-__BUILD_HASH__';\n")
                    (dist / "index.html").write_text(
                        f'<link rel="modulepreload" href="/{glue}" integrity="sha384-test">'
                        f'<link rel="preload" href="/{wasm}" as="fetch" type="application/wasm">'
                        f'<script type="module">\nimport init, * as bindings from "/{glue}";\n'
                        f'const wasm = await init({{ module_or_path: "/{wasm}" }});\n'
                        'window.wasmBindings = bindings;\n'
                        'dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));</script>')
                    finalize(dist)
                files = [{p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
                         for root in roots]
                self.assertEqual(files[0], files[1])
                html = files[0]["index.html"]
                self.assertIn(b'<meta name="af-app-wasm-url"', html)
                self.assertNotIn(b' as="fetch"', html)
                build_hash = hashlib.sha256(html).hexdigest()[:16]
                self.assertIn(build_hash.encode(), files[0]["sw.js"])
                bootstrap, = [name for name in files[0] if re.fullmatch(r"af-bootstrap-[0-9a-f]{16}\.js", name)]
                self.assertIn(b'Promise.all', files[0][bootstrap])
                self.assertIn(b'fetch(', files[0][bootstrap])
                self.assertIn(b'import(', files[0][bootstrap])
                self.assertNotIn(b'window.wasmBindings', files[0][bootstrap])
                self.assertEqual(gzip.decompress(files[0][bootstrap + ".gz"]), files[0][bootstrap])

        def test_unmatched_or_duplicate_application_preloads_fail_closed(self):
            for links, script in [
                ('<link rel="preload" as="fetch" href="/app.wasm">', 'import init from "/app.js"; init();'),
                ('<link rel="preload" as="fetch" href="/other.wasm">',
                 'import init from "/app.js"; const wasm = await init({ module_or_path: "/app.wasm" });'),
                ('<link rel="preload" as="fetch" href="/app.wasm">' * 2,
                 'import init from "/app.js"; const wasm = await init({ module_or_path: "/app.wasm" });'),
            ]:
                with self.subTest(links=links), tempfile.TemporaryDirectory() as tmp:
                    dist = Path(tmp)
                    (dist / "app.wasm").write_bytes(executable)
                    (dist / "other.wasm").write_bytes(executable)
                    (dist / "af-web-worker_bg.wasm").write_bytes(executable)
                    for name in ["af-web-worker.js", "af-web-worker_loader.js"]:
                        (dist / name).write_text("// fixture")
                    (dist / "index.html").write_text(links + f'<script type="module">\n{script}\n</script>')
                    with self.assertRaisesRegex(ValueError, "WASM|preload"):
                        finalize(dist)

        def test_lazy_locales_are_complete_deterministic_and_precompressed(self):
            import ctypes
            import ctypes.util

            with tempfile.TemporaryDirectory() as tmp:
                dist = Path(tmp)
                publish_locales(dist)
                before = {path.name: path.read_bytes() for path in (dist / "locales").iterdir()}
                self.assertEqual(len(before), 15)
                self.assertNotIn("en.json", before)
                for locale in LAZY_LOCALES:
                    data = before[f"{locale}.json"]
                    self.assertLess(len(before[f"{locale}.json.gz"]), len(data))
                    self.assertLess(len(before[f"{locale}.json.br"]), len(data))
                    self.assertEqual(json.loads(data), json.loads((CATALOG_DIR / f"{locale}.json").read_bytes()))
                    self.assertEqual(data, json.dumps(json.loads(data), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())
                    self.assertEqual(gzip.decompress(before[f"{locale}.json.gz"]), data)
                    try:
                        import brotli
                    except ImportError:
                        decoder = ctypes.CDLL(ctypes.util.find_library("brotlidec"))
                        decoder.BrotliDecoderDecompress.argtypes = [
                            ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p,
                        ]
                        decoder.BrotliDecoderDecompress.restype = ctypes.c_int
                        compressed = before[f"{locale}.json.br"]
                        size = ctypes.c_size_t(len(data))
                        output = ctypes.create_string_buffer(len(data))
                        self.assertEqual(decoder.BrotliDecoderDecompress(len(compressed), compressed, ctypes.byref(size), output), 1)
                        self.assertEqual(output.raw[:size.value], data)
                    else:
                        self.assertEqual(brotli.decompress(before[f"{locale}.json.br"]), data)
                publish_locales(dist)
                self.assertEqual(before, {path.name: path.read_bytes() for path in (dist / "locales").iterdir()})

        def test_tiny_locale_catalogs_remove_oversized_sidecars(self):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                catalogs = root / "catalogs"
                catalogs.mkdir()
                (catalogs / "fr.json").write_text("{}")
                dist = root / "dist"
                locales = dist / "locales"
                locales.mkdir(parents=True)
                for extension in ("gz", "br"):
                    (locales / f"fr.json.{extension}").write_bytes(b"stale sidecar")
                with patch.dict(globals(), CATALOG_DIR=catalogs, LAZY_LOCALES=("fr",)):
                    publish_locales(dist)
                self.assertEqual((locales / "fr.json").read_bytes(), b"{}")
                self.assertEqual([path.name for path in locales.iterdir()], ["fr.json"])

        def test_leaked_rsx_in_wasm_and_html_is_rejected_before_publication(self):
            for suffix in (".wasm", ".html"):
                for text in (b"on:click=move |_|", b"on:input=move\n|event|", b"on:change=move |event|", b"on:keydown=move |event|", b"on:submit=move\n  |event|", b"on : click = move | _ |", b"= 24\n"):
                    with self.subTest(suffix=suffix, text=text), tempfile.TemporaryDirectory() as tmp:
                        dist = Path(tmp)
                        (dist / f"app{suffix}").write_bytes(b"prefix " + text + b" suffix")
                        with self.assertRaisesRegex(ValueError, "Leaked RSX closure text"):
                            finalize(dist)
                        self.assertFalse((dist / "locales").exists())

        def test_worker_graph_bootstrap_sri_cache_stamp_and_metadata(self):
            with tempfile.TemporaryDirectory() as tmp:
                dist = Path(tmp)
                (dist / "af-web-worker_bg.wasm").write_bytes(executable + custom("runtime", b"\x00" * 128))
                (dist / "af-web-worker.js").write_text(
                    "fetch('af-web-worker_bg.wasm');\n" + "// worker glue\n" * 16)
                (dist / "af-web-worker_loader.js").write_text(
                    "import './af-web-worker.js';\n" + "// worker loader\n" * 16)
                (dist / ".trunk-lock").touch()
                (dist / ".trunk-temp").mkdir()
                (dist / "assets").mkdir()
                (dist / "assets" / "style.css").write_bytes(b"body { color: red; }\n" * 16)
                style_sri = base64.b64encode(hashlib.sha384((dist / "assets" / "style.css").read_bytes()).digest()).decode("ascii")
                (dist / "manifest.json").write_text(json.dumps({"description": "AetherFlow " * 32}))
                (dist / "assets" / "logo.svg").write_text(
                    '<svg xmlns="http://www.w3.org/2000/svg">' + '<path d="M0 0L10 10"/>' * 32 + '</svg>')
                tiny = dist / "tiny.js"
                tiny.write_bytes(b"//q7B9z2X5v8N1c4M6p0R3s8T2u9W5y1K6j0L4x8")
                self.assertEqual(len(tiny.read_bytes()), 40)
                self.assertGreaterEqual(len(gzip.compress(tiny.read_bytes(), mtime=0)), 40)
                self.assertGreaterEqual(len(compress_brotli(tiny.read_bytes())), 40)
                # A previous build must not leave oversized sidecars behind.
                tiny.with_suffix(".js.gz").write_bytes(b"stale" * 16)
                tiny.with_suffix(".js.br").write_bytes(b"stale" * 16)
                tiny_assets = [tiny, dist / "tiny.json", dist / "tiny.svg"]
                tiny_assets[1].write_bytes(b"{}")
                tiny_assets[2].write_bytes(b"<svg/>")
                (dist / "sw.js").write_text(
                    "const CACHE_NAME = 'aetherflow-cache-wasm-__BUILD_HASH__';\n"
                    + "// service worker\n" * 16)
                (dist / "index.html").write_text(
                    '<meta name="af-worker-url" content="/af-web-worker_loader.js">'
                    f'<link rel="stylesheet" href="/assets/style.css" integrity="sha384-{style_sri}">'
                    f'<link rel="stylesheet" href="/assets/style.css" integrity="sha384-{style_sri}" crossorigin="use-credentials">'
                    '<script type="module">import init, * as bindings from "/app-123.js";'
                    'window.wasmBindings = bindings; init();\n' + '// bootstrap\n' * 16 + '</script>'
                    '<script src="/external.js"></script>')
                with patch(f"{__name__}.compress_brotli", wraps=compress_brotli) as compressor:
                    finalize(dist)
                # Five catalogs and four JSON/SVG files are each encoded once.
                self.assertEqual(compressor.call_count, len(LAZY_LOCALES) + 4)
                html = (dist / "index.html").read_text()
                stylesheet = f'<link rel="stylesheet" href="/assets/style.css" integrity="sha384-{style_sri}" crossorigin="anonymous">'
                self.assertEqual(html.count(stylesheet), 2)
                self.assertNotIn('crossorigin="use-credentials"', html)
                build_hash = hashlib.sha256((dist / "index.html").read_bytes()).hexdigest()[:16]
                self.assertEqual(
                    (dist / "sw.js").read_text(),
                    f"const CACHE_NAME = 'aetherflow-cache-wasm-{build_hash}';\n"
                    + "// service worker\n" * 16,
                )
                bootstrap, = dist.glob("af-bootstrap-*.js")
                data = bootstrap.read_bytes()
                self.assertEqual(bootstrap.stem, f"af-bootstrap-{hashlib.sha256(data).hexdigest()[:16]}")
                sri = base64.b64encode(hashlib.sha384(data).digest()).decode("ascii")
                self.assertIn(f'integrity="sha384-{sri}" crossorigin="anonymous"', html)
                self.assertIn(f'src="/{bootstrap.name}"', html)
                self.assertNotIn(b"window.wasmBindings", data)
                self.assertIn(b"init();", data)
                self.assertFalse(list(dist.rglob(".trunk*")))
                for pattern in ["af-web-worker_bg-*.wasm", "af-web-worker-*.js", "af-web-worker_loader-*.js"]:
                    artifact, = dist.glob(pattern)
                    self.assertIn(hashlib.sha256(artifact.read_bytes()).hexdigest()[:16], artifact.name)
                loader, = dist.glob("af-web-worker_loader-*.js")
                glue, = dist.glob("af-web-worker-*.js")
                wasm, = dist.glob("af-web-worker_bg-*.wasm")
                self.assertIn(glue.name, loader.read_text())
                self.assertIn(wasm.name, glue.read_text())
                audit = ScriptAudit()
                audit.feed(html)
                self.assertEqual(audit.inline_scripts, 0)
                for asset in dist.rglob("*"):
                    if asset in tiny_assets or asset.suffix not in {".wasm", ".js", ".css", ".json", ".svg"}:
                        continue
                    compressed = asset.with_name(asset.name + ".gz").read_bytes()
                    self.assertLess(len(compressed), asset.stat().st_size)
                    self.assertEqual(gzip.decompress(compressed), asset.read_bytes())
                    self.assertEqual(compressed[4:8], b"\x00" * 4)
                    self.assertEqual(
                        compressed, gzip.compress(asset.read_bytes(), compresslevel=9, mtime=0)
                    )
                    if asset.suffix in {".json", ".svg"}:
                        compressed = asset.with_name(asset.name + ".br").read_bytes()
                        self.assertEqual(compressed, compress_brotli(asset.read_bytes()))
                        self.assertLess(len(compressed), asset.stat().st_size)
                for asset in tiny_assets:
                    for extension in ("gz", "br"):
                        self.assertFalse(asset.with_name(f"{asset.name}.{extension}").exists())
                self.assertFalse((dist / "af-web-worker.js.gz").exists())
                self.assertFalse((dist / "index.html.gz").exists())

        def test_unexpected_inline_script_is_rejected(self):
            with tempfile.TemporaryDirectory() as tmp:
                dist = Path(tmp)
                (dist / "af-web-worker_bg.wasm").write_bytes(executable)
                for name in ["af-web-worker.js", "af-web-worker_loader.js"]:
                    (dist / name).write_bytes(b"test")
                (dist / "index.html").write_text('<script>alert(1)</script>')
                with self.assertRaises(ValueError):
                    finalize(dist)

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FinalizerTests))
    if not result.wasSuccessful():
        raise SystemExit(1)


def main():
    import sys
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif len(sys.argv) == 3 and sys.argv[1] == "--locales-only":
        publish_locales(Path(sys.argv[2]))
    elif sys.argv[1:]:
        raise SystemExit("usage: finalize_wasm_assets.py [--self-test | --locales-only DIST]")
    else:
        finalize(Path(os.environ.get("TRUNK_STAGING_DIR", "dist/.stage")))


if __name__ == "__main__":
    main()
