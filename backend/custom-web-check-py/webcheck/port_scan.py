from __future__ import annotations

import asyncio
from typing import Iterable, List, Optional


async def _check_port(host: str, port: int, timeout_ms: int) -> Optional[int]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=max(0.1, timeout_ms / 1000.0),
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port
    except Exception:
        return None


async def scan_ports(host: str, ports: Iterable[int], timeout_ms: int) -> List[int]:
    tasks = [_check_port(host, int(p), timeout_ms) for p in ports]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    out = [p for p in results if isinstance(p, int)]
    out = sorted(set(out))
    return out
