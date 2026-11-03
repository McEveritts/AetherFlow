import argparse
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import textwrap
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arguments-json", required=True)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--bash", action="store_true")
    options = parser.parse_args()
    root = options.root.resolve(strict=True)
    if not root.name.startswith("af-self-update-test-"):
        raise ValueError("refusing an unexpected fixture directory")
    use_user = os.environ.get("AF_SYSTEMD_TEST_USER") == "1"
    scope = ["--user"] if use_user else []
    service_prefix = "af-update-test-" + uuid.uuid4().hex
    caller = service_prefix + "-caller.service"
    updater = service_prefix + "-updater.service"
    fifo = root / "completion.fifo"
    first_pid = root / "first-pid"
    os.mkfifo(fifo, 0o600)
    descriptor = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    arguments = json.loads(options.arguments_json)
    arguments = ["--unit=" + updater if value == "--unit=aetherflow-self-update.service" else value
                 for value in arguments]
    expected = ["deploy", "--channel", "nightly"]
    if not options.bash:
        expected = ["release", "deploy", "--local", "--channel", "nightly"]
    command = ["systemctl", *scope]
    public_reader = command if use_user else ["runuser", "-u", "nobody", "--", *command]
    helper = root / "updater.py"
    helper.write_text(textwrap.dedent(f"""\
        import json, os, pathlib, subprocess, sys
        assert sys.argv[1:] == {expected!r}, sys.argv
        assert os.environ.get('GH_TOKEN') == 'fixture-token'
        public_environment = subprocess.check_output({public_reader + ['show', '--property=Environment', '--value', updater]!r}, text=True)
        assert 'fixture-token' not in public_environment and 'GH_TOKEN' not in public_environment
        subprocess.run({command + ['restart', caller]!r}, check=True, timeout=15)
        current = subprocess.check_output({command + ['show', '--property=MainPID', '--value', caller]!r}, text=True).strip()
        previous = pathlib.Path({str(first_pid)!r}).read_text().strip()
        assert current != previous and int(current) > 0, (current, previous)
        with open({str(fifo)!r}, 'w') as stream:
            json.dump({{'result': 'complete', 'callerRestarted': True}}, stream)
        """), encoding="utf-8")
    if options.bash:
        (root / "release.sh").write_text('exec /usr/bin/python3 ' + str(helper) + ' "$@"\n', encoding="utf-8")
    else:
        (root / "af").write_text("#!/usr/bin/python3\n" + helper.read_text(encoding="utf-8"), encoding="utf-8")
        (root / "af").chmod(0o700)
    launch = ["systemd-run", *scope, *arguments]
    caller_script = root / "caller.py"
    caller_script.write_text(textwrap.dedent(f"""\
        import os, pathlib, signal, subprocess
        marker = pathlib.Path({str(first_pid)!r})
        try:
            with marker.open('x') as stream:
                stream.write(str(os.getpid()))
        except FileExistsError:
            pass
        else:
            subprocess.run({launch!r}, check=True, timeout=15)
        signal.pause()
        """), encoding="utf-8")
    try:
        subprocess.run(["systemd-run", *scope, "--unit=" + caller, "--service-type=exec",
                        "--property=KillMode=control-group", "/usr/bin/python3", str(caller_script)],
                       check=True, timeout=15)
        ready, _, _ = select.select([descriptor], [], [], 25)
        if not ready:
            subprocess.run(["journalctl", *scope, "-u", caller, "-u", updater, "--no-pager", "-n", "35"], check=False)
            raise AssertionError("independent updater did not survive caller restart")
        result = json.loads(os.read(descriptor, 4096).decode())
        assert result == {"result": "complete", "callerRestarted": True}, result
        print("PASS: " + ("Bash" if options.bash else "native") + " updater survived caller restart without exposing credentials")
    finally:
        os.close(descriptor)
        subprocess.run([*command, "stop", caller, updater], check=False, timeout=15)
        subprocess.run([*command, "reset-failed", caller, updater], check=False, timeout=15,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
