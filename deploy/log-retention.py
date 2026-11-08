#!/usr/bin/env python3
"""Periodic, bounded-tail copy/truncate for marketplace lifecycle logs only."""

import argparse
import fcntl
import grp
import os
from pathlib import Path
import pwd
import re
import stat
import sys


DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_KEEP = 3
LOG_NAME = re.compile(r"(?:install\.log|(?:install|remove)-(?P<package>[A-Za-z0-9][A-Za-z0-9._-]{0,63})\.log)\Z")
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class UnsafeLogError(ValueError):
    pass


def _validate_file(descriptor, allowed_owners):
    metadata = os.fstat(descriptor)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_uid not in allowed_owners or metadata.st_mode & 0o022):
        raise UnsafeLogError("expected a singly linked, trusted-owner regular file without group/world writes")
    return metadata


def _open_file(directory, name, flags, allowed_owners):
    descriptor = os.open(name, flags | FILE_FLAGS, 0o600, dir_fd=directory)
    try:
        _validate_file(descriptor, allowed_owners)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _permissions(descriptor, group_id, mode):
    metadata = os.fstat(descriptor)
    if (metadata.st_uid, metadata.st_gid) != (os.geteuid(), group_id):
        os.fchown(descriptor, os.geteuid(), group_id)
    os.fchmod(descriptor, mode)


def _open_directory(path, group_id, allowed_owners):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
        raise UnsafeLogError("log directory must be an absolute, non-root path without '..'")
    descriptor = os.open("/", DIRECTORY_FLAGS)
    try:
        for index, component in enumerate(path.parts[1:]):
            try:
                child = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if index != len(path.parts) - 2:
                    raise
                os.mkdir(component, 0o750, dir_fd=descriptor)
                child = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if metadata.st_uid not in allowed_owners or metadata.st_mode & 0o022:
            raise UnsafeLogError("log directory must have a trusted owner and no group/world writes")
        _permissions(descriptor, group_id, 0o750)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _same_entry(directory, name, expected):
    metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (metadata.st_dev, metadata.st_ino, metadata.st_nlink) != (
            expected.st_dev, expected.st_ino, 1):
        raise UnsafeLogError(f"entry changed during retention: {name}")


def _archive_entries(directory, name, group_id):
    archive_pattern = re.compile(re.escape(name) + r"\.af-retention\.([1-9][0-9]*|pending)\Z")
    archives = {}
    for entry in os.listdir(directory):
        match = archive_pattern.fullmatch(entry)
        if match is None:
            continue
        descriptor = _open_file(directory, entry, os.O_RDONLY, {os.geteuid()})
        try:
            _permissions(descriptor, group_id, 0o640)
            archives[entry] = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    return archives


def _copy_tail(directory, descriptor, pending, max_bytes, group_id):
    destination = _open_file(directory, pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, {os.geteuid()})
    try:
        _permissions(destination, group_id, 0o640)
        size = os.fstat(descriptor).st_size
        offset = max(0, size - max_bytes)
        remaining = size - offset
        while remaining:
            chunk = os.pread(descriptor, min(65536, remaining), offset)
            if not chunk:
                break
            unwritten = memoryview(chunk)
            while unwritten:
                written = os.write(destination, unwritten)
                if written == 0:
                    raise OSError("zero-length archive write")
                unwritten = unwritten[written:]
            offset += len(chunk)
            remaining -= len(chunk)
        os.fsync(destination)
    finally:
        os.close(destination)


def _retain_one(directory, name, max_bytes, keep, group_id, allowed_owners):
    descriptor = _open_file(directory, name, os.O_RDWR, allowed_owners)
    pending = name + ".af-retention.pending"
    try:
        metadata = os.fstat(descriptor)
        archives = _archive_entries(directory, name, group_id)
        _same_entry(directory, name, metadata)
        _permissions(descriptor, group_id, 0o640)
        if pending in archives:
            _same_entry(directory, pending, archives.pop(pending))
            os.unlink(pending, dir_fd=directory)
        for entry, archive in archives.items():
            if int(entry.rsplit(".", 1)[1]) > keep:
                _same_entry(directory, entry, archive)
                os.unlink(entry, dir_fd=directory)
            elif archive.st_size > max_bytes:
                source = _open_file(directory, entry, os.O_RDONLY, {os.geteuid()})
                try:
                    _copy_tail(directory, source, pending, max_bytes, group_id)
                finally:
                    os.close(source)
                _same_entry(directory, entry, archive)
                os.replace(pending, entry, src_dir_fd=directory, dst_dir_fd=directory)
        if os.fstat(descriptor).st_size <= max_bytes:
            return False
        _copy_tail(directory, descriptor, pending, max_bytes, group_id)
        for index in range(keep - 1, 0, -1):
            source = f"{name}.af-retention.{index}"
            try:
                archive_descriptor = _open_file(directory, source, os.O_RDONLY, {os.geteuid()})
            except FileNotFoundError:
                continue
            try:
                _same_entry(directory, source, os.fstat(archive_descriptor))
                os.replace(source, f"{name}.af-retention.{index + 1}",
                           src_dir_fd=directory, dst_dir_fd=directory)
            finally:
                os.close(archive_descriptor)
        os.replace(pending, name + ".af-retention.1", src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        _same_entry(directory, name, metadata)
        _validate_file(descriptor, {os.geteuid()})
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        return True
    finally:
        os.close(descriptor)


def retain_logs(log_dir, max_bytes=DEFAULT_MAX_BYTES, keep=DEFAULT_KEEP, group_id=None, legacy_uid=None):
    """Preserve active inodes; report unsafe entries instead of following them."""
    if not 1 <= max_bytes <= 64 * 1024 * 1024 or not 1 <= keep <= 20:
        raise ValueError("max-bytes must be 1..67108864 and keep must be 1..20")
    group_id = os.getegid() if group_id is None else group_id
    allowed_owners = {os.geteuid()}
    if legacy_uid is not None:
        allowed_owners.add(legacy_uid)
    directory = _open_directory(log_dir, group_id, allowed_owners)
    lock = None
    try:
        lock = _open_file(directory, ".af-retention.lock", os.O_RDWR | os.O_CREAT, {os.geteuid()})
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _permissions(lock, group_id, 0o600)
        rotated = 0
        errors = []
        for name in sorted(os.listdir(directory)):
            match = LOG_NAME.fullmatch(name)
            if match is None or ".." in (match.group("package") or ""):
                continue
            try:
                rotated += _retain_one(directory, name, max_bytes, keep, group_id, allowed_owners)
            except (OSError, ValueError) as error:
                errors.append(f"{name}: {error}")
        return rotated, errors
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", default="/var/log/aetherflow")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--keep", type=int, default=DEFAULT_KEEP)
    parser.add_argument("--group")
    parser.add_argument("--legacy-owner")
    arguments = parser.parse_args()
    try:
        group_id = grp.getgrnam(arguments.group).gr_gid if arguments.group else None
        legacy_uid = pwd.getpwnam(arguments.legacy_owner).pw_uid if arguments.legacy_owner else None
        rotated, errors = retain_logs(arguments.log_dir, arguments.max_bytes, arguments.keep,
                                      group_id, legacy_uid)
    except (OSError, ValueError, KeyError) as error:
        print(f"log retention: {error}", file=sys.stderr)
        return 1
    print(f"log retention: rotated {rotated} lifecycle log(s); rejected {len(errors)}")
    for error in errors:
        print(f"log retention: {error}", file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
