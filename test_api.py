import argparse
import os
import shlex
import sys

import paramiko


def parse_args():
    parser = argparse.ArgumentParser(description="Run remote AetherFlow API diagnostics over SSH.")
    parser.add_argument("--host", default=os.getenv("AETHERFLOW_TEST_HOST"), help="SSH host")
    parser.add_argument("--username", default=os.getenv("AETHERFLOW_TEST_USER"), help="SSH username")
    parser.add_argument("--password", default=os.getenv("AETHERFLOW_TEST_PASSWORD"), help="SSH password")
    parser.add_argument(
        "--sudo-password",
        default=os.getenv("AETHERFLOW_TEST_SUDO_PASSWORD"),
        help="Password used for sudo; defaults to --password when omitted",
    )
    return parser.parse_args()


def require(value, flag_name):
    if value:
        return value
    print(f"Missing required value for {flag_name}. Provide it via CLI or environment.", file=sys.stderr)
    raise SystemExit(1)


def exec_sudo_command(client, sudo_password, command):
    quoted_password = shlex.quote(sudo_password)
    quoted_command = shlex.quote(command)
    stdin, stdout, stderr = client.exec_command(
        f"printf '%s\\n' {quoted_password} | sudo -S -p '' sh -lc {quoted_command}"
    )
    output = stdout.read().decode("ascii", errors="ignore")
    error = stderr.read().decode("ascii", errors="ignore")
    if error:
        print(error, file=sys.stderr)
    return output


def run():
    args = parse_args()
    host = require(args.host, "--host / AETHERFLOW_TEST_HOST")
    username = require(args.username, "--username / AETHERFLOW_TEST_USER")
    password = require(args.password, "--password / AETHERFLOW_TEST_PASSWORD")
    sudo_password = args.sudo_password or password

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username=username, password=password)

        print("--- NETSTAT OUT ---")
        print(exec_sudo_command(client, sudo_password, "netstat -tulpn | grep 8080"))

        print("--- LSOF OUT ---")
        print(exec_sudo_command(client, sudo_password, "lsof -i :8080"))
    finally:
        client.close()


if __name__ == "__main__":
    run()
