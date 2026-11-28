"""Exercise the runner self-update route with two real systemd services in CI."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import uuid


def wait_for(path, seconds=25):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file():
            return path.read_text(encoding="utf-8")
        time.sleep(0.1)
    raise TimeoutError(f"Timed out waiting for {path.name}")


def systemctl(*args):
    return subprocess.check_output(["systemctl", *args], text=True, timeout=15).strip()


def fake_release_worker(root, caller, engine, args):
    if engine == "native":
        expected = ["--root", str(root), "release", "deploy", "--channel", "nightly", "--local"]
    else:
        assert engine == "bash"
        expected = ["deploy", "--channel", "nightly", "--root", str(root)]
    assert args[:len(expected)] == expected, args
    flags = dict(zip(args[len(expected)::2], args[len(expected) + 1::2]))
    receipt = Path(flags["--job-status-file"])
    config = Path(flags["--config"])
    updater = flags["--job-unit"]
    assert receipt.parent == config.parent
    assert receipt.stem == config.stem == updater
    assert config.resolve().is_relative_to(root)
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert receipt == Path(os.environ["AETHERFLOW_SELF_UPDATE_STATUS_FILE"])
    assert config == Path(os.environ["AETHERFLOW_RELEASE_CONF"])
    assert config.is_file()
    public_environment = subprocess.check_output(
        ["runuser", "-u", "nobody", "--", "systemctl", "show",
         "--property=Environment", "--value", updater],
        text=True,
        timeout=15,
    )
    assert "af-fixture-token" not in public_environment
    assert os.environ.get("GH_TOKEN") != "af-fixture-token"
    assert wait_for(root / "admitted") == updater
    original_pid = int(wait_for(root / "caller-pid"))
    systemctl("restart", caller)
    replacement_pid = int(systemctl("show", "--property=MainPID", "--value", caller))
    assert replacement_pid > 0 and replacement_pid != original_pid
    status = json.loads(receipt.read_text(encoding="utf-8"))
    assert status["status"] == "running", status
    status.update(status="succeeded", completed=True, success=True, exit_code=0)
    temporary = receipt.with_suffix(".fixture")
    with os.fdopen(os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as stream:
        json.dump(status, stream)
    temporary.replace(receipt)
    (root / "worker-complete").touch()


def smoke(binary, engine):
    caller = "af-update-test-" + uuid.uuid4().hex + ".service"
    with tempfile.TemporaryDirectory(prefix="af-self-update-test-", dir="/var/tmp") as directory, \
            tempfile.TemporaryDirectory(prefix="af-self-update-bin-", dir="/run") as bin_directory:
        root = Path(directory)
        # As root, the runner only executes AETHERFLOW_CLI_BIN / AETHERFLOW_RELEASE_MANAGER_SCRIPT
        # when the file and every ancestor directory are root-owned and not group/world-writable,
        # with no sticky-bit exemption (is_trusted_runner_target). The sticky, world-writable
        # /var/tmp therefore cannot hold the fake worker, so keep it under root-owned /run.
        bin_dir = Path(bin_directory)
        for ancestor in (bin_dir, *bin_dir.parents):
            info = ancestor.lstat()
            assert info.st_uid == 0 and not stat.S_ISLNK(info.st_mode) and not info.st_mode & 0o022, (
                f"untrusted fake-worker ancestor {ancestor}"
            )
        worker = bin_dir / "af"
        worker.write_text(
            f"#!/bin/sh\nexec /usr/bin/python3 '{Path(__file__).resolve()}' "
            f"--worker '{root}' '{caller}' '{engine}' \"$@\"\n",
            encoding="utf-8",
        )
        worker.chmod(0o700)
        environment = {
            "AF_SELF_UPDATE_SMOKE_ROOT": root,
            "AETHERFLOW_RELEASE_ROOT": root,
            "AETHERFLOW_ENABLE_RUST_RELEASE": "1",
            "AETHERFLOW_FORCE_BASH_RELEASE": "1" if engine == "bash" else "0",
            "AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE": "1",
            "AETHERFLOW_SYSTEMD_RUN_BIN": "/usr/bin/systemd-run",
            "AETHERFLOW_CLI_BIN": worker,
            "AETHERFLOW_RELEASE_MANAGER_SCRIPT": worker,
            "GH_TOKEN": "af-fixture-token",
        }
        try:
            subprocess.run(
                ["systemd-run", "--collect", f"--unit={caller}", "--service-type=exec",
                 "--property=KillMode=control-group",
                 *(f"--setenv={name}={value}" for name, value in environment.items()),
                 "--", str(binary), "tests::self_update_smoke_caller", "--ignored", "--exact", "--nocapture"],
                check=True,
                timeout=15,
            )
            wait_for(root / "verified")
            print(f"PASS: /v1/self-update {engine} worker survived caller restart")
        except Exception:
            units = [caller]
            if (root / "admitted").is_file():
                units.append((root / "admitted").read_text(encoding="utf-8"))
            subprocess.run(
                ["journalctl", *(arg for unit in units for arg in ("-u", unit)),
                 "--no-pager", "-n", "50"],
                check=False,
                timeout=15,
            )
            raise
        finally:
            jobs = root / "var/lib/aetherflow/.self-update-jobs"
            units = [caller, *(file.stem for file in jobs.glob("aetherflow-self-update-*.json"))]
            subprocess.run(["systemctl", "stop", *units], check=False, timeout=15)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        fake_release_worker(Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5:])
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument("--test-binary", required=True, type=Path)
        binary = parser.parse_args().test_binary.resolve(strict=True)
        for engine in ("native", "bash"):
            smoke(binary, engine)
