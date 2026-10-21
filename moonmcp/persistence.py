"""Private atomic persistence and cooperating thread/process file locks."""

from __future__ import annotations

import contextlib
import errno
import os
import stat
import tempfile
import threading
from collections.abc import Iterator
from typing import Any

_LOCKS: dict[str, Any] = {}
_LOCKS_GUARD = threading.Lock()
_HELD = threading.local()


@contextlib.contextmanager
def path_lock(path: str | os.PathLike[str]) -> Iterator[None]:
    """Serialize cooperating users of a path; retain the adjacent lock inode.

    Nested acquisition by one thread shares the already-held process lock.
    POSIX uses flock and Windows uses a one-byte msvcrt lock. This coordinates
    cooperating writers in independently initialized processes; it does not
    authorize an untrusted state directory. Reusing these locks after forking
    during active persistence operations is unsupported.
    """
    key = os.path.normcase(os.path.abspath(os.fspath(path)))
    with _LOCKS_GUARD:
        lock = _LOCKS.setdefault(key, threading.RLock())
    with lock:
        held = getattr(_HELD, "paths", None)
        if held is None:
            held = _HELD.paths = {}
        if key in held:
            yield
            return
        lock_path = key + ".lock"
        parent = os.path.dirname(lock_path)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
        if not hasattr(os, "O_NOFOLLOW") and os.path.islink(lock_path):
            raise OSError(errno.ELOOP, "Persistence lock must not be a symlink", lock_path)
        fd = os.open(lock_path, flags, 0o600)
        acquired = False
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(errno.EINVAL, "Persistence lock must be a regular file", lock_path)
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            if os.name == "nt":
                import msvcrt

                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX)
            acquired = True
            held[key] = fd
            yield
        finally:
            held.pop(key, None)
            try:
                if acquired:
                    if os.name == "nt":
                        import msvcrt

                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
                    else:
                        import fcntl

                        fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def fsync_directory(path: str) -> None:
    """Persist directory entry changes on platforms supporting directory fsync."""
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: str, data: bytes, *, fsync: bool = True) -> None:
    """Replace one private file atomically; the caller owns any transaction lock."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".",
                                     suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            if fsync:
                os.fsync(stream.fileno())
        os.replace(temporary, path)
        if fsync:
            fsync_directory(parent)
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
