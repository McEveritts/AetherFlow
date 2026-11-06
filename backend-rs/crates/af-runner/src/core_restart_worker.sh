set -euo pipefail
exec python3 - "$@" <<'PY'
import fcntl
import json
import os
import pathlib
import stat
import subprocess
import sys
import uuid

if len(sys.argv) != 10:
    sys.exit("Core restart refused: scheduled receipt directory identity is required")
service, status_name, unit, lock_name, systemctl, device, inode, receipt_device, receipt_inode = sys.argv[1:]
expected = (int(device), int(inode))
expected_directory = (int(receipt_device), int(receipt_inode))
path = pathlib.Path(status_name)

def identity(metadata):
    return metadata.st_dev, metadata.st_ino

class Directory:
    def __init__(self, name):
        parts = pathlib.PurePosixPath(name).parts
        if not parts or parts[0] != "/" or ".." in parts:
            raise RuntimeError("Receipt and lock paths must be absolute and non-traversing")
        self.chain = [(None, os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC))]
        try:
            for component in parts[1:]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
                self.chain.append((component, child))
            self.verify()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.chain[-1][1]

    def verify(self):
        for index, (component, descriptor) in enumerate(self.chain):
            held = os.fstat(descriptor)
            if not stat.S_ISDIR(held.st_mode) or held.st_nlink == 0:
                raise RuntimeError("Receipt or lock directory disappeared")
            if index:
                entry = os.stat(component, dir_fd=self.chain[index - 1][1], follow_symlinks=False)
                if not stat.S_ISDIR(entry.st_mode) or identity(entry) != identity(held):
                    raise RuntimeError("Receipt or lock directory identity changed")

    def close(self):
        for _, descriptor in reversed(self.chain):
            os.close(descriptor)
        self.chain = []

def verify_file(directory, name, descriptor):
    directory.verify()
    held = os.fstat(descriptor)
    entry = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    if not stat.S_ISREG(held.st_mode) or held.st_nlink != 1 or identity(entry) != identity(held) or not stat.S_ISREG(entry.st_mode):
        raise RuntimeError("Receipt or lock is not a private regular file with a stable identity")

def open_file(directory, name, flags, mode=0o600):
    directory.verify()
    descriptor = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, mode, dir_fd=directory.fd)
    try:
        verify_file(directory, name, descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

def open_lock():
    parts = pathlib.PurePosixPath(lock_name).parts
    if not parts or parts[0] != "/" or ".." in parts:
        raise RuntimeError("Maintenance lock requires an absolute, non-traversing path")
    directory = Directory(str(pathlib.PurePosixPath(lock_name).parent))
    try:
        descriptor = open_file(directory, parts[-1], os.O_RDONLY)
    finally:
        directory.close()
    metadata = os.fstat(descriptor)
    if identity(metadata) != expected:
        os.close(descriptor)
        raise RuntimeError("Maintenance lock identity changed or is not a regular file")
    return descriptor

def receipt(phase, code=0):
    directory.verify()
    descriptor = open_file(directory, path.name + ".lock", os.O_RDWR | os.O_CREAT)
    temporary = None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        verify_file(directory, path.name + ".lock", descriptor)
        source_fd = open_file(directory, path.name, os.O_RDONLY)
        with os.fdopen(source_fd, encoding="utf-8") as source:
            current = json.load(source)
            verify_file(directory, path.name, source.fileno())
            source_identity = identity(os.fstat(source.fileno()))
        if current.get("job_unit") != unit:
            raise RuntimeError("Core restart receipt identity does not match")
        if current.get("completed"):
            if phase == "claim":
                raise RuntimeError("Core restart admission was closed")
            return
        payload = {
            "job_unit": unit,
            "status": "running" if phase == "claim" else ("succeeded" if code == 0 else "failed"),
            "completed": phase != "claim",
            "success": phase != "claim" and code == 0,
            "exit_code": None if phase == "claim" else code,
            "error": "Core restart failed; inspect service logs and readiness." if code else "",
        }
        temporary = path.name + ".tmp." + uuid.uuid4().hex
        output_fd = open_file(directory, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(output_fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o644)
            json.dump(payload, output)
            output.flush()
            os.fsync(output.fileno())
            verify_file(directory, temporary, output.fileno())
            verify_file(directory, path.name + ".lock", descriptor)
            destination = os.stat(path.name, dir_fd=directory.fd, follow_symlinks=False)
            if not stat.S_ISREG(destination.st_mode) or destination.st_nlink != 1 or identity(destination) != source_identity:
                raise RuntimeError("Core restart receipt changed during update")
            os.replace(temporary, path.name, src_dir_fd=directory.fd, dst_dir_fd=directory.fd)
            temporary = None
            verify_file(directory, path.name, output.fileno())
            os.fsync(directory.fd)
    finally:
        try:
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory.fd)
                except FileNotFoundError:
                    pass
        finally:
            os.close(descriptor)

directory = None
try:
    guard = open_lock()
    fcntl.flock(guard, fcntl.LOCK_EX)
    verification = open_lock()
    os.close(verification)
    directory = Directory(str(path.parent))
    if identity(os.fstat(directory.fd)) != expected_directory:
        raise RuntimeError("Scheduled receipt directory identity changed")
    receipt("claim")
    directory.verify()
    code = subprocess.run([systemctl, "restart", "--", service], close_fds=True, pass_fds=(guard,)).returncode
    if code == 0:
        directory.verify()
        code = subprocess.run([systemctl, "is-active", "--quiet", "--", service], close_fds=True, pass_fds=(guard,)).returncode
    receipt("complete", code if code >= 0 else 1)
    sys.exit(code if code >= 0 else 1)
except Exception as error:
    print(f"Core restart refused: {error}", file=sys.stderr)
    if directory is not None and identity(os.fstat(directory.fd)) == expected_directory:
        try:
            receipt("complete", 1)
        except Exception as completion_error:
            print(f"Core restart receipt refused: {completion_error}", file=sys.stderr)
    sys.exit(1)
finally:
    if directory is not None:
        directory.close()
PY
