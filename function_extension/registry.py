"""Registry of the simulated devices running in this process.

Every device is served by its own ``MyServer`` in its own thread, but they all
live in one process. Some behaviours span two devices — an RSCONTROL hub paired
with an RSPower strip, a strip socket driven by a probe of the hub — so each
server registers itself here and a handler can reach its peer by name or by
hardware id, as the real devices identify each other on the wire.

Cross-device reads and writes are done under ``LOCK``: two devices may be
serving a request at the same time.
"""

from __future__ import annotations

import threading
from typing import Any, Iterator, Optional

LOCK = threading.RLock()

_SERVERS: dict[str, Any] = {}


def register(server: Any) -> None:
    """Make a device reachable by the others (keyed by its config name)."""
    with LOCK:
        _SERVERS[server.config.name] = server


def unregister(server: Any) -> None:
    """Forget a device (tests, or a server shutting down)."""
    with LOCK:
        if _SERVERS.get(server.config.name) is server:
            del _SERVERS[server.config.name]


def clear() -> None:
    """Forget every device (tests)."""
    with LOCK:
        _SERVERS.clear()


def servers() -> Iterator[Any]:
    """Every registered device."""
    with LOCK:
        return iter(list(_SERVERS.values()))


def hwid(server: Any) -> str:
    """Hardware id a device reports (derived from its config name)."""
    return str(server.hw_id_for(server.config.name))


def by_name(name: Optional[str]) -> Optional[Any]:
    """The device configured under ``name``, if running."""
    if not name:
        return None
    with LOCK:
        return _SERVERS.get(name)


def by_hwid(value: Optional[str]) -> Optional[Any]:
    """The device whose hardware id is ``value``, if running."""
    if not value:
        return None
    for server in servers():
        if hwid(server) == value:
            return server
    return None
