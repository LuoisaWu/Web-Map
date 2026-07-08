from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse


_TITLE_RE = re.compile(r"<title[^>]*>([^<]+)</title>", re.IGNORECASE)
_META_DESC_RE = re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
_META_DESC_RE2 = re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']description["\']', re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.DOTALL | re.IGNORECASE)
_STYLE_RE = re.compile(r"<style[^>]*>.*?</style>", re.DOTALL | re.IGNORECASE)
_WS_RE = re.compile(r"\s+")
_ICP_RE = re.compile(r"((?:[\u4e00-\u9fa5])?ICP备\d+号(?:-\d+)?|公网安备\s*\d+号)", re.IGNORECASE)


def normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items() if k is not None}


def detect_waf(headers: Dict[str, str]) -> str:
    h = normalize_headers(headers)
    server = str(h.get("server", "")).lower()
    if "cf-ray" in h or "cloudflare" in server:
        return "Cloudflare"
    if "x-sucuri-id" in h or "x-sucuri-cache" in h:
        return "Sucuri"
    if "x-akamai-transformed" in h or "akamai" in server:
        return "Akamai"
    if "imperva" in server or "x-iinfo" in h or h.get("x-cdn", "") == "incapsula":
        return "Imperva/Incapsula"
    return "Unknown"


def extract_title(html: str) -> str:
    m = _TITLE_RE.search(html)
    if not m:
        return ""
    return m.group(1).strip()[:100]


def extract_icp(html: str) -> str:
    m = _ICP_RE.search(html)
    if not m:
        return ""
    return m.group(1).strip()[:50]


def extract_meta_description(html: str) -> str:
    m = _META_DESC_RE.search(html) or _META_DESC_RE2.search(html)
    if not m:
        return ""
    return m.group(1).strip()[:300]


def extract_body_text(html: str, max_chars: int = 500) -> str:
    # Remove scripts and styles
    text = _SCRIPT_RE.sub(" ", html)
    text = _STYLE_RE.sub(" ", text)
    # Remove HTML tags
    text = _TAG_RE.sub(" ", text)
    # Collapse whitespace
    text = _WS_RE.sub(" ", text)
    return text.strip()[:max_chars]


def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT")
    return ctx


async def _read_headers(reader: asyncio.StreamReader, timeout_s: float) -> Tuple[Optional[str], Dict[str, str], bytes]:
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout_s)
    except Exception:
        return None, {}, b""

    head, rest = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    if not lines:
        return None, {}, rest
    try:
        status_line = lines[0].decode("iso-8859-1", "ignore")
    except Exception:
        status_line = None
    headers: Dict[str, str] = {}
    for ln in lines[1:]:
        if b":" not in ln:
            continue
        k, v = ln.split(b":", 1)
        key = k.decode("iso-8859-1", "ignore").strip().lower()
        val = v.decode("iso-8859-1", "ignore").strip()
        if key in headers:
            headers[key] = headers[key] + ", " + val
        else:
            headers[key] = val
    return status_line, headers, rest


async def _read_body(
    reader: asyncio.StreamReader,
    headers: Dict[str, str],
    first_chunk: bytes,
    max_bytes: int,
    timeout_s: float,
) -> bytes:
    buf = bytearray()
    if first_chunk:
        buf.extend(first_chunk[:max_bytes])
    remaining = max_bytes - len(buf)
    if remaining <= 0:
        return bytes(buf)

    te = headers.get("transfer-encoding", "").lower()
    if "chunked" in te:
        return bytes(buf) + await _read_chunked(reader, remaining, timeout_s)

    cl = headers.get("content-length")
    if cl and cl.isdigit():
        to_read = min(int(cl), remaining)
        try:
            data = await asyncio.wait_for(reader.readexactly(to_read), timeout=timeout_s)
            return bytes(buf) + data
        except Exception:
            return bytes(buf)

    while remaining > 0:
        try:
            chunk = await asyncio.wait_for(reader.read(min(65536, remaining)), timeout=timeout_s)
        except Exception:
            break
        if not chunk:
            break
        buf.extend(chunk)
        remaining = max_bytes - len(buf)
    return bytes(buf)


async def _read_chunked(reader: asyncio.StreamReader, max_bytes: int, timeout_s: float) -> bytes:
    out = bytearray()
    while len(out) < max_bytes:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout_s)
        except Exception:
            break
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            size = int(line.split(b";", 1)[0], 16)
        except Exception:
            break
        if size == 0:
            try:
                await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout_s)
            except Exception:
                pass
            break
        to_take = min(size, max_bytes - len(out))
        try:
            chunk = await asyncio.wait_for(reader.readexactly(size), timeout=timeout_s)
        except Exception:
            break
        out.extend(chunk[:to_take])
        try:
            await asyncio.wait_for(reader.readexactly(2), timeout=timeout_s)
        except Exception:
            break
    return bytes(out)


@dataclass
class RequestOptions:
    timeout_ms: int = 10000
    max_redirects: int = 3
    max_bytes: int = 262144
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    host_header: str = ""
    servername: str = ""


async def request_once(url: str, opts: RequestOptions) -> dict:
    try:
        u = urlparse(url)
    except Exception:
        return {"ok": False, "error": "InvalidURL", "url": url}

    scheme = (u.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return {"ok": False, "error": "InvalidURL", "url": url}

    host = u.hostname or ""
    if not host:
        return {"ok": False, "error": "InvalidURL", "url": url}

    try:
        port = u.port or (443 if scheme == "https" else 80)
    except ValueError:
        return {"ok": False, "error": "InvalidPort", "url": url}
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    timeout_s = max(0.1, opts.timeout_ms / 1000.0)
    ssl_ctx = _make_ssl_context() if scheme == "https" else None
    servername = opts.servername or host

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=servername if ssl_ctx else None),
            timeout=timeout_s,
        )
    except Exception:
        return {"ok": False, "error": "Timeout", "url": url}

    try:
        host_header = opts.host_header or host
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: {opts.user_agent}\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
            f"Accept-Encoding: identity\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        writer.write(req.encode("utf-8", "ignore"))
        await asyncio.wait_for(writer.drain(), timeout=timeout_s)

        status_line, headers, first = await _read_headers(reader, timeout_s)
        if not status_line:
            return {"ok": False, "error": "ReadError", "url": url}
        m = re.match(r"^HTTP/\d+\.\d+\s+(\d+)", status_line)
        if not m:
            return {"ok": False, "error": "ReadError", "url": url}
        status = int(m.group(1))
        body = await _read_body(reader, headers, first, opts.max_bytes, timeout_s)
        return {"ok": True, "statusCode": status, "headers": headers, "body": body, "url": url}
    except Exception:
        return {"ok": False, "error": "RequestError", "url": url}
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def fetch_with_redirects(start_url: str, opts: RequestOptions) -> dict:
    current = start_url
    redirect_chain: List[Dict[str, object]] = []
    for i in range(0, max(0, opts.max_redirects) + 1):
        r = await request_once(current, opts)
        if not r.get("ok"):
            return {**r, "redirectChain": redirect_chain}
        status = int(r.get("statusCode") or 0)
        h = normalize_headers(r.get("headers") or {})
        loc = h.get("location")
        redirect_chain.append({"url": current, "status": status, "location": loc or ""})
        if status in {301, 302, 303, 307, 308} and loc and i < opts.max_redirects:
            try:
                current = urljoin(current, loc)
                continue
            except Exception:
                return {**r, "redirectChain": redirect_chain}
        return {**r, "redirectChain": redirect_chain}
    return {"ok": False, "error": "RedirectLoop", "url": start_url, "redirectChain": redirect_chain}


async def probe_web(base_url: str, opts: RequestOptions) -> dict:
    r = await fetch_with_redirects(base_url, opts)
    if not r.get("ok"):
        return {
            "ok": False,
            "status": r.get("error") or "Error",
            "title": "N/A",
            "server": "N/A",
            "xPoweredBy": "N/A",
            "setCookie": "N/A",
            "via": "N/A",
            "hsts": "N/A",
            "waf": "N/A",
            "finalUrl": "N/A",
            "redirectChain": r.get("redirectChain") or [],
            "icp": "N/A",
        }

    headers = normalize_headers(r.get("headers") or {})
    content_type = str(headers.get("content-type", ""))
    title = ""
    icp = ""
    meta_desc = ""
    body_text = ""
    if "text/html" in content_type.lower():
        try:
            text = (r.get("body") or b"").decode("utf-8", "ignore")
        except Exception:
            text = ""
        title = extract_title(text)
        icp = extract_icp(text)
        meta_desc = extract_meta_description(text)
        body_text = extract_body_text(text)

    return {
        "ok": True,
        "status": r.get("statusCode"),
        "title": title or "N/A",
        "server": headers.get("server", "N/A") or "N/A",
        "xPoweredBy": headers.get("x-powered-by", "N/A") or "N/A",
        "setCookie": "Present" if "set-cookie" in headers else "N/A",
        "via": headers.get("via", "N/A") or "N/A",
        "hsts": "Yes" if "strict-transport-security" in headers else "No",
        "waf": detect_waf(headers),
        "finalUrl": r.get("url") or base_url,
        "redirectChain": r.get("redirectChain") or [],
        "icp": icp or "N/A",
        "contentType": headers.get("content-type", "N/A") or "N/A",
        "csp": headers.get("content-security-policy", "N/A") or "N/A",
        "xFrameOptions": headers.get("x-frame-options", "N/A") or "N/A",
        "xContentTypeOptions": headers.get("x-content-type-options", "N/A") or "N/A",
        "referrerPolicy": headers.get("referrer-policy", "N/A") or "N/A",
        "permissionsPolicy": headers.get("permissions-policy", "N/A") or "N/A",
        "cookieCount": str(len([k for k in headers if k == "set-cookie"])),
        "metaDescription": meta_desc or "N/A",
        "bodyText": body_text or "N/A",
    }
