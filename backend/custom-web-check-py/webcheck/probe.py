from __future__ import annotations

import asyncio
import base64
import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .dns_client import resolve_dns_records
from .http_probe import RequestOptions, probe_web, request_once
from .murmurhash3 import murmurhash3_x86_32
from .port_scan import scan_ports
from .ssl_probe import get_ssl_best_effort


CSV_HEADER = "Rank,Domain,IP_A,IP_AAAA,DNS_CNAME,DNS_MX,DNS_TXT,DNS_NS,Open_Ports,Favicon_Hash,HTTP_Status,Title,Server,X_Powered_By,WAF_Detect,Via_Proxy,Set_Cookie,HSTS,SSL_Issuer,SSL_Subject,SSL_Valid_From,SSL_Valid_To\n"
CSV_HEADER_V2 = "Rank,Domain,IP_A,IP_AAAA,DNS_CNAME,DNS_MX,DNS_TXT,DNS_NS,Open_Ports,Favicon_Hash,HTTP_Status,Title,Server,X_Powered_By,WAF_Detect,Via_Proxy,Set_Cookie,HSTS,SSL_Issuer,SSL_Subject,SSL_Valid_From,SSL_Valid_To,Meta_Description,Body_Text\n"
CSV_HEADER_CHINA = CSV_HEADER_V2.strip() + ",ICP_License\n"


def escape_csv(value) -> str:
    if value is None:
        return '"N/A"'
    if value == "":
        return '"N/A"'
    s = str(value)
    if s == "":
        return '"N/A"'
    return '"' + s.replace('"', '""') + '"'


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def normalize_target(raw: str) -> Dict[str, str]:
    if raw is None:
        return {"input": "", "hostname": "", "raw_hostname": "", "display": ""}
    input_s = str(raw).strip()
    if not input_s:
        return {"input": "", "hostname": "", "raw_hostname": "", "display": ""}
    raw_hostname = input_s
    hostname = input_s
    try:
        if "://" in input_s:
            raw_hostname = urlparse(input_s).hostname or input_s
            hostname = raw_hostname
        elif "/" in input_s:
            raw_hostname = urlparse("http://" + input_s).hostname or input_s
            hostname = raw_hostname
    except Exception:
        hostname = input_s
    hostname = hostname.replace("www.", "", 1) if hostname.lower().startswith("www.") else hostname
    return {"input": input_s, "hostname": hostname, "raw_hostname": raw_hostname, "display": hostname or input_s}


def _build_base_url(scheme: str, host: str, open_ports: List[int]) -> str:
    s = (scheme or "").lower()
    if s == "https":
        if 443 in open_ports:
            return f"https://{host}"
        if 8443 in open_ports:
            return f"https://{host}:8443"
        if 9443 in open_ports:
            return f"https://{host}:9443"
        return f"https://{host}"

    if 80 in open_ports:
        return f"http://{host}"
    if 8080 in open_ports:
        return f"http://{host}:8080"
    if open_ports and 80 not in open_ports:
        return f"http://{host}:{open_ports[0]}"
    return f"http://{host}"


def _origin_of(url: str) -> str:
    try:
        u = urlparse(url)
        if u.scheme and u.netloc:
            return f"{u.scheme}://{u.netloc}"
    except Exception:
        pass
    return ""


def _score_http_result(base_url: str, http_info: dict) -> Tuple[int, int, int, int, int]:
    status = http_info.get("status")
    ok = bool(http_info.get("ok"))
    is_timeout = status == "Timeout"
    non_timeout = 0 if is_timeout else 1
    title = http_info.get("title")
    has_title = 1 if title not in {None, "", "N/A"} else 0
    is_https = 1 if str(base_url).lower().startswith("https://") else 0
    code = status if isinstance(status, int) else 0
    code_class = int(code / 100) if code else 0
    code_score = 0
    if code_class == 2:
        code_score = 4
    elif code_class == 3:
        code_score = 3
    elif code_class == 4:
        code_score = 2
    elif code_class == 5:
        code_score = 1
    return (non_timeout, 1 if ok else 0, has_title, is_https, code_score)


async def get_favicon_hash(base_url: str, opts: RequestOptions) -> str:
    try:
        u = urlparse(base_url)
        fav_url = f"{u.scheme}://{u.netloc}/favicon.ico"
        r = await request_once(fav_url, RequestOptions(**{**opts.__dict__, "max_bytes": 1024 * 1024}))
        if not r.get("ok"):
            return "Timeout" if r.get("error") == "Timeout" else "Error"
        if int(r.get("statusCode") or 0) != 200:
            return "N/A"
        body = r.get("body") or b""
        b64 = base64.b64encode(body).decode("ascii", "ignore")
        lines = [b64[i : i + 76] for i in range(0, len(b64), 76)]
        s = "\n".join(lines) + "\n"
        h = murmurhash3_x86_32(s.encode("utf-8"), 0)
        return str(h)
    except Exception:
        return "Error"


@dataclass
class GlobalOptions:
    ports_to_scan: List[int]
    port_timeout_ms: int
    request_opts: RequestOptions
    sni: str = ""
    host_header: str = ""
    dns_resolvers: Optional[List[str]] = None


@dataclass
class ProbeResult:
    csv_row: str
    rank: str
    domain: str
    base_url: str
    final_url: str
    redirect_chain: List[Dict[str, object]]
    icp: str
    is_china: bool
    http: dict
    ssl: dict
    dns: dict


async def run_probe_task(target_info: Dict[str, str], global_opts: GlobalOptions) -> Optional[ProbeResult]:
    input_s = target_info.get("input", "")
    hostname = target_info.get("hostname", "")
    raw_hostname = target_info.get("raw_hostname", "") or hostname
    display = target_info.get("display", "")
    rank = target_info.get("rank", "N/A")
    if not hostname:
        return None

    base_req_opts = RequestOptions(**global_opts.request_opts.__dict__)

    print("Starting dns_task and ports_task")
    dns_task = resolve_dns_records(
        hostname,
        resolvers=global_opts.dns_resolvers,
        timeout_ms=min(2000, base_req_opts.timeout_ms),
    )
    ports_task = scan_ports(hostname, global_opts.ports_to_scan, global_opts.port_timeout_ms)
    print("Gathering...")
    dns_info, open_ports = await asyncio.gather(dns_task, ports_task)
    print("Gathered dns and ports")

    open_ports_str = ", ".join(str(p) for p in open_ports) if open_ports else "None/Timeout"

    if input_s.startswith("http://") or input_s.startswith("https://"):
        candidates = [input_s]
    else:
        if is_ip(hostname):
            candidate_hosts = [hostname]
        else:
            if str(raw_hostname).lower().startswith("www."):
                candidate_hosts = [raw_hostname]
            else:
                candidate_hosts = [hostname, "www." + hostname]

        candidates = []
        for h in candidate_hosts:
            candidates.append(_build_base_url("https", h, open_ports))
        for h in candidate_hosts:
            candidates.append(_build_base_url("http", h, open_ports))

    seen = set()
    base_urls = []
    for u in candidates:
        k = str(u).strip()
        if not k or k in seen:
            continue
        seen.add(k)
        base_urls.append(k)

    async def probe_one(base_url: str) -> dict:
        req_opts = RequestOptions(**base_req_opts.__dict__)
        connect_host = urlparse(base_url).hostname or hostname
        host_header = global_opts.host_header or connect_host
        servername = global_opts.sni or global_opts.host_header or connect_host
        req_opts.host_header = host_header
        req_opts.servername = servername
        r = await probe_web(base_url, req_opts)
        r["baseUrl"] = base_url
        return r

    http_results = await asyncio.gather(*[probe_one(u) for u in base_urls], return_exceptions=False)
    best_http = http_results[0] if http_results else {"ok": False, "status": "Error", "title": "N/A", "finalUrl": "N/A"}
    best_score = _score_http_result(best_http.get("baseUrl") or "", best_http)
    for r in http_results[1:]:
        s = _score_http_result(r.get("baseUrl") or "", r)
        if s > best_score:
            best_score = s
            best_http = r

    selected_base_url = best_http.get("baseUrl") or (base_urls[0] if base_urls else "")
    selected_final_url = best_http.get("finalUrl") or "N/A"
    redirect_chain = best_http.get("redirectChain") or []

    fav_origin = _origin_of(selected_final_url) or _origin_of(selected_base_url) or selected_base_url
    fav_host = urlparse(fav_origin).hostname or hostname
    fav_req_opts = RequestOptions(**base_req_opts.__dict__)
    fav_req_opts.host_header = global_opts.host_header or fav_host
    fav_req_opts.servername = global_opts.sni or global_opts.host_header or fav_host

    ssl_host = urlparse(selected_base_url).hostname or hostname
    ssl_servername = global_opts.sni or global_opts.host_header or ssl_host

    fav_task = get_favicon_hash(fav_origin, fav_req_opts)
    ssl_task = get_ssl_best_effort(ssl_host, open_ports, ssl_servername, base_req_opts.timeout_ms)
    favicon_hash, ssl_info = await asyncio.gather(fav_task, ssl_task, return_exceptions=False)

    row = [
        rank,
        display,
        dns_info.get("a", "N/A"),
        dns_info.get("aaaa", "N/A"),
        dns_info.get("cname", "N/A"),
        dns_info.get("mx", "N/A"),
        dns_info.get("txt", "N/A"),
        dns_info.get("ns", "N/A"),
        open_ports_str,
        favicon_hash,
        best_http.get("status", "N/A"),
        best_http.get("title", "N/A"),
        best_http.get("server", "N/A"),
        best_http.get("xPoweredBy", "N/A"),
        best_http.get("waf", "N/A"),
        best_http.get("via", "N/A"),
        best_http.get("setCookie", "N/A"),
        best_http.get("hsts", "N/A"),
        ssl_info.get("issuer", "N/A"),
        ssl_info.get("subject", "N/A"),
        ssl_info.get("validFrom", "N/A"),
        ssl_info.get("validTo", "N/A"),
        best_http.get("metaDescription", "N/A"),
        best_http.get("bodyText", "N/A"),
    ]
    csv_row = ",".join(escape_csv(x) for x in row)

    icp = str(best_http.get("icp", "N/A"))
    title = str(best_http.get("title", ""))
    
    is_china = False
    if icp != "N/A" and icp != "":
        is_china = True
    elif str(display).lower().endswith((".cn", ".com.cn", ".net.cn", ".org.cn", ".gov.cn", ".edu.cn")):
        is_china = True
    elif title != "N/A" and re.search(r'[\u4e00-\u9fa5]', title):
        is_china = True

    return ProbeResult(
        csv_row=csv_row,
        rank=str(rank),
        domain=str(display),
        base_url=str(selected_base_url),
        final_url=str(selected_final_url),
        redirect_chain=redirect_chain if isinstance(redirect_chain, list) else [],
        icp=icp,
        is_china=is_china,
        http={
            "status": best_http.get("status", "N/A"),
            "title": best_http.get("title", "N/A"),
            "server": best_http.get("server", "N/A"),
            "xPoweredBy": best_http.get("xPoweredBy", "N/A"),
            "waf": best_http.get("waf", "N/A"),
            "via": best_http.get("via", "N/A"),
            "setCookie": best_http.get("setCookie", "N/A"),
            "hsts": best_http.get("hsts", "N/A"),
            "contentType": best_http.get("contentType", "N/A"),
            "csp": best_http.get("csp", "N/A"),
            "xFrameOptions": best_http.get("xFrameOptions", "N/A"),
            "xContentTypeOptions": best_http.get("xContentTypeOptions", "N/A"),
            "referrerPolicy": best_http.get("referrerPolicy", "N/A"),
            "permissionsPolicy": best_http.get("permissionsPolicy", "N/A"),
            "cookieCount": best_http.get("cookieCount", "0"),
        },
        ssl={
            "issuer": ssl_info.get("issuer", "N/A"),
            "subject": ssl_info.get("subject", "N/A"),
            "validFrom": ssl_info.get("validFrom", "N/A"),
            "validTo": ssl_info.get("validTo", "N/A"),
        },
        dns={
            "a": dns_info.get("a", "N/A"),
            "cname": dns_info.get("cname", "N/A"),
            "ns": dns_info.get("ns", "N/A"),
            "mx": dns_info.get("mx", "N/A"),
        },
    )
