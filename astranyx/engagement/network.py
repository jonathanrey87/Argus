"""DNS and cross-process pacing controls for authorized HTTP execution."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit


class ResolutionDenied(PermissionError):
    """Raised when DNS resolution crosses the engagement network boundary."""


class SystemResolver:
    """Resolve a URL host once; callers must bind transport to the result."""

    def resolve(self, host: str, port: int) -> tuple[str, ...]:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        }
        if not addresses:
            raise ResolutionDenied("target hostname did not resolve")
        return tuple(sorted(addresses, key=lambda value: (":" in value, value)))


class SharedRateLimiter:
    """Reserve per-origin request slots safely across clients and processes."""

    schema_version = 1

    def __init__(
        self,
        path: str | Path,
        requests_per_second: float,
        *,
        clock: Callable[[], float] = time.time,
        sleeper: Callable[[float], None] = time.sleep,
    ):
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive")
        self.path = Path(path).expanduser()
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.interval = 1.0 / requests_per_second
        self.clock = clock
        self.sleeper = sleeper
        self._thread_lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink() or self.lock_path.is_symlink():
            raise ValueError("rate state paths must not be symbolic links")

    @contextmanager
    def _exclusive_lock(self):
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.lock_path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        try:
            if os.name == "nt":
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"\0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _read(self) -> dict[str, float]:
        if not self.path.exists():
            return {}
        flags = os.O_RDONLY | (getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(self.path, flags)
        try:
            payload = os.read(descriptor, 1_048_577)
        finally:
            os.close(descriptor)
        if len(payload) > 1_048_576:
            raise ValueError("rate state exceeds size bound")
        try:
            document = json.loads(payload)
            if document.get("schema_version") != self.schema_version:
                raise ValueError
            return {
                str(key): float(value) for key, value in document["origins"].items()
            }
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("invalid shared rate state") from exc

    def _write(self, origins: dict[str, float]) -> None:
        payload = json.dumps(
            {"schema_version": self.schema_version, "origins": origins},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        temporary = self.path.with_name(
            f"{self.path.name}.tmp-{os.getpid()}-{threading.get_ident()}"
        )
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("rate state write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.path)

    def wait(self, url: str = "") -> None:
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
        origin = f"{parsed.scheme.casefold()}://{parsed.hostname}:{port}"
        with self._thread_lock, self._exclusive_lock():
            current = self.clock()
            origins = self._read()
            next_allowed = origins.get(origin, current)
            if next_allowed > current + 3600:
                raise ValueError("shared rate state is unreasonably far in the future")
            if next_allowed < current - 3600:
                next_allowed = current
            reservation = max(current, next_allowed)
            origins[origin] = reservation + self.interval
            self._write(origins)
        delay = reservation - current
        if delay > 0:
            self.sleeper(delay)


def address_is_global(value: str) -> bool:
    """Return whether an address is globally routable under ipaddress semantics."""
    return ipaddress.ip_address(value).is_global
