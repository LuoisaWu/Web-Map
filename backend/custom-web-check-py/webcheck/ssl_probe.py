from __future__ import annotations

import asyncio
import os
import ssl
import tempfile
from typing import Dict, List


def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _pick_name(entry: List[tuple], key: str) -> str:
    for item in entry:
        if len(item) == 2 and item[0] == key and item[1]:
            return str(item[1])
    return ""


def _extract_org_or_cn(name_seq) -> str:
    if not name_seq:
        return "Unknown"
    flat = []
    for rdn in name_seq:
        for k, v in rdn:
            flat.append((k, v))
    org = _pick_name(flat, "organizationName")
    if org:
        return org
    cn = _pick_name(flat, "commonName")
    if cn:
        return cn
    return "Unknown"


async def get_ssl(host: str, port: int, servername: str, timeout_ms: int) -> Dict[str, str]:
    timeout_s = max(0.1, timeout_ms / 1000.0)
    ctx = _make_ssl_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=servername or host),
            timeout=timeout_s,
        )
    except Exception:
        return {"issuer": "Timeout", "subject": "Timeout", "validFrom": "Timeout", "validTo": "Timeout"}

    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if not ssl_obj:
            return {"issuer": "N/A", "subject": "N/A", "validFrom": "N/A", "validTo": "N/A"}
        der = ssl_obj.getpeercert(binary_form=True)
        if not der:
            return {"issuer": "N/A", "subject": "N/A", "validFrom": "N/A", "validTo": "N/A"}
        pem = ssl.DER_cert_to_PEM_cert(der)
        tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem")
        try:
            tmp.write(pem)
            tmp.flush()
            tmp.close()
            decoded = ssl._ssl._test_decode_cert(tmp.name)
        finally:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
        issuer = _extract_org_or_cn(decoded.get("issuer"))
        subject = _extract_org_or_cn(decoded.get("subject"))
        not_before = decoded.get("notBefore") or "N/A"
        not_after = decoded.get("notAfter") or "N/A"
        return {"issuer": issuer, "subject": subject, "validFrom": not_before, "validTo": not_after}
    except Exception:
        return {"issuer": "Error", "subject": "Error", "validFrom": "Error", "validTo": "Error"}
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def get_ssl_best_effort(host: str, open_ports: List[int], servername: str, timeout_ms: int) -> Dict[str, str]:
    candidates = [p for p in [443, 8443, 9443] if p in open_ports]
    ports_to_try = candidates or [443]
    for p in ports_to_try:
        r = await get_ssl(host, p, servername, timeout_ms)
        if r.get("issuer") not in {"Error", "Timeout"}:
            return r
    return await get_ssl(host, ports_to_try[0], servername, timeout_ms)
