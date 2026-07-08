from __future__ import annotations

import asyncio
import os
import random
import socket
from typing import Iterable, List, Optional, Tuple


_QTYPE = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}


def _encode_name(name: str) -> bytes:
    name = name.strip(".")
    if not name:
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        b = label.encode("utf-8", "ignore")
        out.append(len(b) & 0xFF)
        out.extend(b)
    out.append(0)
    return bytes(out)


def _decode_name(msg: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    original_offset = offset
    seen = 0

    while True:
        if offset >= len(msg):
            return "", offset
        length = msg[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(msg):
                return "", offset + 1
            ptr = ((length & 0x3F) << 8) | msg[offset + 1]
            offset += 2
            if not jumped:
                original_offset = offset
                jumped = True
            offset = ptr
            seen += 1
            if seen > 20:
                break
            continue
        offset += 1
        label = msg[offset : offset + length].decode("utf-8", "ignore")
        labels.append(label)
        offset += length

    name = ".".join([x for x in labels if x])
    return name, (original_offset if jumped else offset)


def _build_query(qname: str, qtype: int) -> Tuple[int, bytes]:
    txid = random.randint(0, 0xFFFF)
    flags = 0x0100
    header = txid.to_bytes(2, "big") + flags.to_bytes(2, "big") + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    question = _encode_name(qname) + qtype.to_bytes(2, "big") + b"\x00\x01"
    return txid, header + question


async def _udp_request(server: str, payload: bytes, timeout_s: float) -> Optional[bytes]:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    print(f"_udp_request to {server}")
    try:
        await loop.sock_sendto(sock, payload, (server, 53))
        print(f"sendto done")
        data = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=timeout_s)
        print(f"recv done")
        return data
    except Exception as e:
        print(f"exception: {e}")
        return None
    finally:
        sock.close()


def _parse_response(msg: bytes, txid: int) -> Tuple[int, int, int, int, int]:
    if len(msg) < 12:
        return 0, 0, 0, 0, 0
    rid = int.from_bytes(msg[0:2], "big")
    if rid != txid:
        return 0, 0, 0, 0, 0
    flags = int.from_bytes(msg[2:4], "big")
    qd = int.from_bytes(msg[4:6], "big")
    an = int.from_bytes(msg[6:8], "big")
    ns = int.from_bytes(msg[8:10], "big")
    ar = int.from_bytes(msg[10:12], "big")
    rcode = flags & 0x000F
    return rcode, qd, an, ns, ar


def _extract_records(msg: bytes, qd: int, an: int) -> List[Tuple[int, bytes]]:
    offset = 12
    for _ in range(qd):
        _, offset = _decode_name(msg, offset)
        offset += 4

    out: List[Tuple[int, bytes]] = []
    for _ in range(an):
        _, offset = _decode_name(msg, offset)
        if offset + 10 > len(msg):
            break
        rtype = int.from_bytes(msg[offset : offset + 2], "big")
        offset += 2
        offset += 2
        offset += 4
        rdlen = int.from_bytes(msg[offset : offset + 2], "big")
        offset += 2
        rdata = msg[offset : offset + rdlen]
        offset += rdlen
        out.append((rtype, rdata))
    return out


def _decode_rdata_name(msg: bytes, rdata: bytes) -> str:
    combined = msg + rdata
    name, _ = _decode_name(combined, len(msg))
    return name


async def resolve_dns_records(
    hostname: str,
    resolvers: Optional[Iterable[str]] = None,
    timeout_ms: int = 1500,
) -> dict:
    if not hostname:
        return {"a": "N/A", "aaaa": "N/A", "mx": "N/A", "txt": "N/A", "ns": "N/A", "cname": "N/A"}

    timeout_s = max(0.1, timeout_ms / 1000.0)
    resolvers_list = [x for x in (resolvers or []) if x]
    if not resolvers_list:
        env = os.environ.get("WEBMAP_DNS")
        if env:
            resolvers_list = [x.strip() for x in env.split(",") if x.strip()]
    if not resolvers_list:
        resolvers_list = ["1.1.1.1", "8.8.8.8"]

    async def query_one(qname: str, qtype_name: str) -> List[str]:
        qtype = _QTYPE[qtype_name]
        txid, payload = _build_query(qname, qtype)
        for server in resolvers_list:
            resp = await _udp_request(server, payload, timeout_s)
            if not resp:
                continue
            rcode, qd, an, _, _ = _parse_response(resp, txid)
            if rcode != 0 or an <= 0:
                continue
            records = _extract_records(resp, qd, an)
            values: List[str] = []
            for rtype, rdata in records:
                if rtype != qtype:
                    continue
                if qtype_name == "A" and len(rdata) == 4:
                    values.append(socket.inet_ntoa(rdata))
                elif qtype_name == "AAAA" and len(rdata) == 16:
                    values.append(socket.inet_ntop(socket.AF_INET6, rdata))
                elif qtype_name in {"CNAME", "NS"}:
                    values.append(_decode_rdata_name(resp, rdata))
                elif qtype_name == "MX" and len(rdata) >= 3:
                    values.append(_decode_rdata_name(resp, rdata[2:]))
                elif qtype_name == "TXT" and len(rdata) >= 1:
                    i = 0
                    parts: List[str] = []
                    while i < len(rdata):
                        ln = rdata[i]
                        i += 1
                        s = rdata[i : i + ln].decode("utf-8", "ignore")
                        i += ln
                        if s:
                            parts.append(s)
                    if parts:
                        values.append("".join(parts))
            if values:
                return values
        return []

    async def system_a_records() -> Tuple[List[str], List[str]]:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        except Exception:
            return [], []
        v4: List[str] = []
        v6: List[str] = []
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                v4.append(sockaddr[0])
            elif family == socket.AF_INET6:
                v6.append(sockaddr[0])
        v4 = list(dict.fromkeys(v4))
        v6 = list(dict.fromkeys(v6))
        return v4, v6

    a_sys, aaaa_sys = await system_a_records()
    cname = await query_one(hostname, "CNAME")
    mx = await query_one(hostname, "MX")
    txt = await query_one(hostname, "TXT")
    ns = await query_one(hostname, "NS")

    a = a_sys or await query_one(hostname, "A")
    aaaa = aaaa_sys or await query_one(hostname, "AAAA")

    def fmt(items: List[str], sep: str = ", ") -> str:
        if not items:
            return "N/A"
        items = [x for x in items if x]
        items = list(dict.fromkeys(items))
        if not items:
            return "N/A"
        return sep.join(items)

    return {
        "a": fmt(a, ", "),
        "aaaa": fmt(aaaa, ", "),
        "mx": fmt(mx, ", "),
        "txt": fmt(txt, " | "),
        "ns": fmt(ns, ", "),
        "cname": fmt(cname, ", "),
    }
