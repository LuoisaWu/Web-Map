print("Starting api_server.py")
import uvicorn
import asyncio
import sqlite3
import uuid
import csv
import io
import re
import httpx
import os
import torch
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from transformers import AutoTokenizer, AutoModelForSequenceClassification

import sys
sys.path.append('custom-web-check-py')
sys.path.append('pipeline')
from webcheck.http_probe import RequestOptions
from webcheck.probe import GlobalOptions, run_probe_task, normalize_target
import config as pipeline_config

print("Imports done")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(os.path.dirname(BASE_DIR), "database", "assets_topology.db")
app = FastAPI(title="Omniscience 资产测绘 API")

# 解决跨域问题（允许前端随意调用后端）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ModelService:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.categories = pipeline_config.CATEGORIES
        self.threshold = pipeline_config.MULTI_LABEL_THRESHOLD
        self.model_path = os.path.join(os.path.dirname(__file__), "pipeline", "saved_models", "best_student_model")

    def load_model(self):
        if self.model is None:
            if os.path.exists(self.model_path):
                try:
                    self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
                    self.model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
                    self.model = self.model.to(self.device)
                    self.model.eval()
                except Exception as e:
                    print(f"Model load failed (maybe missing weights?): {e}. Mocking inference.")
                    self.model = None
            else:
                print("Model not found. Mocking inference.")

    def predict(self, text: str) -> list:
        if not text:
            return []
        self.load_model()
        if self.model is None:
            return self._mock_predict(text)

        inputs = self.tokenizer(
            [text],
            add_special_tokens=True,
            max_length=256,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        ).to(self.device)

        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.sigmoid(outputs.logits)[0]
            labels = [self.categories[j] for j, p in enumerate(probs) if p.item() >= self.threshold]
            return labels

    def _mock_predict(self, text: str) -> list:
        labels = []
        t = text.lower()
        if "shop" in t or "store" in t or "buy" in t or "cart" in t:
            labels.append("Ecommerce")
        if "login" in t or "portal" in t:
            labels.append("Corporate")
        if "news" in t or "blog" in t:
            labels.append("News")
        if "gov" in t:
            labels.append("Government")
        if "bank" in t or "payment" in t:
            labels.append("Finance")
        if "university" in t or "school" in t or "college" in t:
            labels.append("Education")
        if "cloud" in t or "storage" in t:
            labels.append("CloudStorage")
        return labels if labels else ["Corporate"]

model_service = ModelService()

def clean_html(html: str) -> str:
    text = re.sub(r'<[^>]+>', ' ', html)
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:1000]

TECH_SIGNATURES = {
    "React": [r'react(?:\.prod(?:uction)?)?\.min\.js', r'react-dom', r'__REACT_DEVTOOLS_GLOBAL_HOOK__', r'_next/', r'__NEXT_DATA__'],
    "Vue.js": [r'vue(?:\.runtime)?(?:\..+)?\.min\.js', r'__VUE_DEVTOOLS_GLOBAL_HOOK__', r'<[^>]+data-v-[a-f0-9]{8}', r'nuxt\.js'],
    "Angular": [r'@angular/', r'ng-version=', r'angular(?:\.min)?\.js'],
    "jQuery": [r'jquery[.-][\d.]+(?:\.min)?\.js', r'jquery\.js'],
    "Bootstrap": [r'bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)', r'class="[^"]*btn(?:-primary|-secondary|-danger|-warning|-info)'],
    "Tailwind CSS": [r'tailwindcss', r'tailwind\.config'],
    "Google Analytics": [r'googletagmanager\.com/gtag', r'google-analytics\.com/analytics\.js', r'gtag\s*\(', r'ga\s*\(\s*[\'"]create[\'"]'],
    "百度统计": [r'hm\.baidu\.com/hm\.js', r'_hmt\s*=', r'baidu\.com/stat/', r'hm\.baidu\.com'],
    "WordPress": [r'wp-content/', r'wordpress', r'wp-includes/'],
    "Drupal": [r'drupal\.js', r'misc/drupal\.js'],
    "Nginx": [r'nginx'],
    "Apache": [r'apache'],
    "IIS": [r'microsoft-iis', r'iis'],
    "Cloudflare": [r'cloudflare'],
    "PHP": [r'x-powered-by[:\s]*php', r'PHPSESSID'],
    "Font Awesome": [r'font-?awesome', r'fa-solid', r'fa-brands'],
    "阿里云": [r'aliyuncs\.com', r'aliyun\.com', r'aliyuncdn'],
    "腾讯云": [r'qcloud\.com', r'myqcloud\.com', r'gtimg\.cn', r'gtimg\.com', r'cdn-go\.cn'],
    "微信": [r'res\.wx\.qq\.com', r'jsapi\.qq\.com', r'mp\.weixin\.qq\.com'],
    "Tengine": [r'tengine'],
    "OpenResty": [r'openresty'],
}

# Header-based detection (doesn't need HTML)
HEADER_TECH_MAP = {
    "Cloudflare": [("server", "cloudflare"), ("cf-ray", None)],
    "阿里云": [("server", "aliyun"), ("server", "tengine")],
    "腾讯云": [("server", "tencent"), ("server", "stgw")],
    "Nginx": [("server", "nginx")],
    "Apache": [("server", "apache")],
    "IIS": [("server", "microsoft-iis")],
    "OpenResty": [("server", "openresty")],
    "Tengine": [("server", "tengine")],
    "Vue.js": [("x-powered-by", "nuxt")],
    "Next.js": [("x-powered-by", "next")],
}

def detect_tech_stack(html: str, server: str, x_powered_by: str, content_type: str) -> list:
    """Detect technology stack from HTML body and HTTP headers."""
    combined = (html + " " + server + " " + x_powered_by + " " + content_type).lower()
    detected = []

    # HTML body regex detection
    for tech, patterns in TECH_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, combined, re.IGNORECASE):
                detected.append(tech)
                break

    # Header-based detection
    headers_lower = {"server": server.lower(), "x-powered-by": x_powered_by.lower()}
    for tech, checks in HEADER_TECH_MAP.items():
        if tech in detected:
            continue
        for key, val in checks:
            header_val = headers_lower.get(key, "")
            if val is None:
                if header_val and header_val != "n/a":
                    detected.append(tech)
                    break
            elif val in header_val:
                detected.append(tech)
                break

    return detected

def audit_security_headers(http_info: dict) -> dict:
    """Audit security headers presence and quality."""
    return {
        "csp": http_info.get("csp", "N/A") if http_info.get("csp", "N/A") != "N/A" else None,
        "xFrameOptions": http_info.get("xFrameOptions", "N/A") if http_info.get("xFrameOptions", "N/A") != "N/A" else None,
        "xContentTypeOptions": http_info.get("xContentTypeOptions", "N/A") if http_info.get("xContentTypeOptions", "N/A") != "N/A" else None,
        "referrerPolicy": http_info.get("referrerPolicy", "N/A") if http_info.get("referrerPolicy", "N/A") != "N/A" else None,
        "permissionsPolicy": http_info.get("permissionsPolicy", "N/A") if http_info.get("permissionsPolicy", "N/A") != "N/A" else None,
        "hsts": http_info.get("hsts", "No") == "Yes",
        "cookieCount": int(http_info.get("cookieCount", "0") or "0"),
    }

# 1. 初始化数据库 (模拟您的测绘数据入库)
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 创建资产节点表 (记录域名、IP、经纬度、分类标签等)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY,
            domain TEXT,
            ip TEXT,
            loc TEXT,
            lat REAL,
            lng REAL,
            type TEXT,
            tags TEXT,
            details TEXT
        )
    """)
    
    # 创建拓扑边表 (记录资产之间的关联，如：同IP、同证书、跳转链接)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS edges (
            source TEXT,
            target TEXT,
            type TEXT
        )
    """)
    
    # 如果数据库为空，插入基于您业务的测试数据
    cursor.execute("SELECT COUNT(*) FROM nodes")
    if cursor.fetchone()[0] == 0:
        print("初始化数据库，插入测试资产数据...")
        nodes = [
            ("1", "example.com", "104.21.34.22", "San Francisco, US", 37.7749, -122.4194, "normal", "电商平台,B2B 业务"),
            ("2", "shop-example.com", "192.168.1.1", "New York, US", 40.7128, -74.0060, "normal", "电商平台"),
            ("3", "global-trade.net", "8.8.8.8", "London, UK", 51.5074, -0.1278, "normal", "贸易门户"),
            ("4", "b2b-portal.org", "1.1.1.1", "Tokyo, JP", 35.6895, 139.6917, "normal", "B2B 业务"),
            ("5", "cdn-node-1.net", "172.64.10.1", "Singapore", 1.3521, 103.8198, "cdn", "CDN分发"),
            ("6", "scam-site-A.com", "45.12.33.1", "Moscow, RU", 55.7558, 37.6173, "scam", "高危站群"),
            ("7", "scam-site-B.com", "45.12.33.2", "St Petersburg, RU", 59.9343, 30.3351, "scam", "高危站群"),
            ("8", "analytics-tracker.com", "8.8.4.4", "Paris, FR", 48.8566, 2.3522, "normal", "数据分析"),
            ("9", "malicious-redirect.org", "103.22.11.0", "Sydney, AU", -33.8688, 151.2093, "scam", "恶意重定向")
        ]
        edges = [
            ("6", "7", "ssl"),
            ("6", "9", "ssl"),
            ("1", "3", "ip"),
            ("1", "5", "cdn"),
            ("2", "5", "cdn"),
            ("8", "5", "cdn"),
            ("4", "1", "link"),
            ("8", "1", "link"),
            ("8", "2", "link")
        ]
        cursor.executemany(
            "INSERT INTO nodes (id, domain, ip, loc, lat, lng, type, tags) VALUES (?,?,?,?,?,?,?,?)",
            nodes
        )
        cursor.executemany("INSERT INTO edges VALUES (?,?,?)", edges)
        conn.commit()
    conn.close()

init_db()

probing_tasks = set()
DEFAULT_TOPOLOGY_LIMIT = 300
OVERVIEW_CANDIDATE_LIMIT = 3000
SEARCH_RESULT_LIMIT = 300
RELATED_NODE_LIMIT = 300
EDGE_LIMIT = 1000
DYNAMIC_EDGE_LIMIT = 1200

EMPTY_VALUES = {"", "unknown", "n/a", "none", "null", "no", "false", "timeout", "error"}
GENERIC_DOMAIN_TOKENS = {
    "www", "com", "net", "org", "cn", "gov", "edu", "co", "io", "ai", "dev",
    "cloud", "cdn", "static", "img", "image", "api", "app", "docs", "www2",
}

def clean_relation_key(value):
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        value = ",".join(str(item) for item in value if item)
    value = re.sub(r"\s+", " ", str(value)).strip()
    if value.lower() in EMPTY_VALUES:
        return ""
    return value

def domain_parts(domain):
    domain = clean_relation_key(domain).lower().strip(".")
    if not domain or "." not in domain:
        return "", ""
    parts = [part for part in domain.split(".") if part]
    if len(parts) < 2:
        return domain, ""
    base = ".".join(parts[-2:])
    brand = parts[-2]
    if brand in GENERIC_DOMAIN_TOKENS and len(parts) >= 3:
        brand = parts[-3]
    return base, brand

def add_group_edges(edges_result, seen_edges, groups, relation_type, label, limit):
    for key, items in groups.items():
        if len(items) < 2:
            continue
        capped = items[:8]
        for index, source in enumerate(capped):
            for target in capped[index + 1:]:
                edge_key = tuple(sorted((source["id"], target["id"])) + [relation_type])
                if edge_key in seen_edges:
                    continue
                edges_result.append({
                    "from": source["id"],
                    "to": target["id"],
                    "type": relation_type,
                    "evidence": f"{label}: {key}",
                })
                seen_edges.add(edge_key)
                if len(edges_result) >= limit:
                    return

def build_dynamic_edges(nodes_result, edges_result, limit=DYNAMIC_EDGE_LIMIT):
    seen_edges = {
        tuple(sorted((edge["from"], edge["to"])) + [edge["type"]])
        for edge in edges_result
    }
    groups = {
        "ssl": {},
        "fingerprint": {},
        "asn": {},
        "domain": {},
    }

    for node in nodes_result:
        domain = clean_relation_key(node.get("domain"))
        base_domain, brand_token = domain_parts(domain)
        if base_domain:
            groups["domain"].setdefault(base_domain, []).append(node)
        if brand_token and len(brand_token) >= 4 and brand_token not in GENERIC_DOMAIN_TOKENS:
            groups["domain"].setdefault(f"brand:{brand_token}", []).append(node)

        details = node.get("details") or {}
        ssl_subject = clean_relation_key(details.get("ssl_subject"))
        ssl_issuer = clean_relation_key(details.get("ssl_issuer"))
        if ssl_subject and len(ssl_subject) > 8:
            groups["ssl"].setdefault(f"{ssl_subject} / {ssl_issuer}" if ssl_issuer else ssl_subject, []).append(node)

        favicon_hash = clean_relation_key(details.get("favicon_hash"))
        if favicon_hash:
            groups["fingerprint"].setdefault(favicon_hash, []).append(node)

        asn = clean_relation_key(node.get("asn") or details.get("asn"))
        if asn and not asn.lower().startswith("unknown"):
            groups["asn"].setdefault(asn, []).append(node)

    add_group_edges(edges_result, seen_edges, groups["ssl"], "ssl", "same certificate", limit)
    add_group_edges(edges_result, seen_edges, groups["fingerprint"], "fingerprint", "same favicon fingerprint", limit)
    add_group_edges(edges_result, seen_edges, groups["asn"], "asn", "same ASN/provider", limit)
    add_group_edges(edges_result, seen_edges, groups["domain"], "domain", "same domain family/brand", limit)

    domain_to_node = {
        clean_relation_key(node.get("domain")).lower(): node
        for node in nodes_result
        if clean_relation_key(node.get("domain"))
    }
    for source in nodes_result:
        details = source.get("details") or {}
        text = clean_relation_key(details.get("text_feature"))
        links = details.get("links") or details.get("outbound_links") or details.get("external_links") or []
        if isinstance(links, str):
            link_text = links
        else:
            link_text = " ".join(str(item) for item in links if item)
        haystack = f"{text} {link_text}".lower()
        if not haystack:
            continue
        for domain, target in domain_to_node.items():
            if source["id"] == target["id"] or domain not in haystack:
                continue
            edge_key = (source["id"], target["id"], "link")
            if edge_key in seen_edges:
                continue
            edges_result.append({
                "from": source["id"],
                "to": target["id"],
                "type": "link",
                "evidence": f"references {target['domain']}",
            })
            seen_edges.add(edge_key)
            if len(edges_result) >= limit:
                return edges_result

    return edges_result

def append_dynamic_related_rows(cursor, rows, limit=RELATED_NODE_LIMIT):
    """Add likely related DB rows by shared evidence before dynamic edges are built."""
    import json

    seen_ids = {row[0] for row in rows}
    related_rows = []
    keys = []
    domain_keys = []

    for row in rows:
        base_domain, brand_token = domain_parts(row[1])
        if base_domain:
            domain_keys.append(("base", base_domain))
        if brand_token and len(brand_token) >= 4 and brand_token not in GENERIC_DOMAIN_TOKENS:
            domain_keys.append(("brand", brand_token))

        details_data = None
        if len(row) > 8 and row[8]:
            try:
                details_data = json.loads(row[8])
            except Exception:
                details_data = None
        if not details_data:
            continue

        ssl_subject = clean_relation_key(details_data.get("ssl_subject"))
        favicon_hash = clean_relation_key(details_data.get("favicon_hash"))
        asn = clean_relation_key(details_data.get("asn"))

        if ssl_subject and len(ssl_subject) > 8:
            keys.append(("details", ssl_subject))
        if favicon_hash:
            keys.append(("details", favicon_hash))
        if asn and not asn.lower().startswith("unknown"):
            keys.append(("details", asn))

    for key_type, key in domain_keys:
        if len(related_rows) >= limit:
            break
        if key_type == "base":
            cursor.execute(
                "SELECT * FROM nodes WHERE domain = ? OR domain LIKE ? LIMIT ?",
                (key, f"%.{key}", min(40, limit - len(related_rows)))
            )
        else:
            cursor.execute(
                "SELECT * FROM nodes WHERE domain LIKE ? LIMIT ?",
                (f"%{key}%", min(40, limit - len(related_rows)))
            )
        for candidate in cursor.fetchall():
            if candidate[0] in seen_ids:
                continue
            related_rows.append(candidate)
            seen_ids.add(candidate[0])
            if len(related_rows) >= limit:
                break

    for _field, key in keys:
        if len(related_rows) >= limit:
            break
        cursor.execute(
            "SELECT * FROM nodes WHERE details LIKE ? LIMIT ?",
            (f"%{key}%", min(30, limit - len(related_rows))),
        )
        for candidate in cursor.fetchall():
            if candidate[0] in seen_ids:
                continue
            related_rows.append(candidate)
            seen_ids.add(candidate[0])
            if len(related_rows) >= limit:
                break

    if related_rows:
        rows.extend(related_rows)

def get_global_stats(cursor):
    cursor.execute("SELECT COUNT(*) FROM nodes")
    total_nodes = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM edges")
    total_edges = cursor.fetchone()[0]

    cursor.execute("SELECT type, tags FROM nodes")
    risk_nodes = 0
    infra_nodes = 0
    risk_tags = {"Adult", "Gambling", "Phishing", "Malware"}
    infra_tags = {"CDN", "WAF", "DNS", "Hosting", "CloudService", "StaticSite", "API"}
    for node_type, tags_value in cursor.fetchall():
        tags = {tag.strip() for tag in (tags_value or "").split(",") if tag.strip()}
        if node_type == "scam" or tags.intersection(risk_tags):
            risk_nodes += 1
        if node_type == "cdn" or tags.intersection(infra_tags):
            infra_nodes += 1

    return {
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "risk_nodes": risk_nodes,
        "infra_nodes": infra_nodes,
    }

def geo_bucket(row):
    lat = row[4]
    lng = row[5]
    if lat is None or lng is None or (lat == 0 and lng == 0):
        return "unknown"
    if lng < -30:
        return "americas-north" if lat >= 0 else "americas-south"
    if lng < 60:
        return "emea-north" if lat >= 0 else "emea-south"
    return "apac-north" if lat >= 0 else "apac-south"

def balanced_overview_rows(cursor, limit):
    cursor.execute(
        """
        SELECT * FROM nodes
        ORDER BY
            CASE WHEN lat IS NOT NULL AND lng IS NOT NULL AND (lat != 0 OR lng != 0) THEN 0 ELSE 1 END,
            RANDOM()
        LIMIT ?
        """,
        (max(limit, OVERVIEW_CANDIDATE_LIMIT),)
    )
    candidates = cursor.fetchall()
    buckets = {}
    for row in candidates:
        buckets.setdefault(geo_bucket(row), []).append(row)

    ordered_keys = [
        "apac-north",
        "emea-north",
        "americas-north",
        "apac-south",
        "emea-south",
        "americas-south",
        "unknown",
    ]
    selected = []
    seen = set()
    while len(selected) < limit:
        added = False
        for key in ordered_keys:
            rows = buckets.get(key) or []
            if not rows:
                continue
            row = rows.pop(0)
            if row[0] in seen:
                continue
            selected.append(row)
            seen.add(row[0])
            added = True
            if len(selected) >= limit:
                break
        if not added:
            break
    return selected

async def lookup_ip_geo(ip: str) -> dict:
    """Query ip-api.com for free IP geolocation (no API key, 45 req/min limit)."""
    if not ip or ip == "N/A" or ip.startswith("Unknown"):
        return {"loc": "Unknown", "lat": 0.0, "lng": 0.0, "asn": "Unknown"}
    first_ip = ip.split(",")[0].strip()
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(f"http://ip-api.com/json/{first_ip}", timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "loc": f"{data.get('city', '')}, {data.get('countryCode', '')}".strip(", "),
                        "lat": data.get("lat", 0.0),
                        "lng": data.get("lon", 0.0),
                        "asn": f"{data.get('as', 'Unknown')} ({data.get('isp', '')})".strip(" ()"),
                    }
    except Exception:
        pass
    return {"loc": "Unknown", "lat": 0.0, "lng": 0.0, "asn": "Unknown"}

async def fetch_html(url: str) -> str:
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(url, timeout=5.0)
            return resp.text
    except Exception:
        return ""

def parse_csv_row(row_str):
    reader = csv.reader(io.StringIO(row_str))
    return next(reader)

async def run_probe_and_save(keyword: str):
    try:
        req = RequestOptions(timeout_ms=10000, max_redirects=3)
        opts = GlobalOptions(ports_to_scan=[80, 443], port_timeout_ms=2000, request_opts=req)
        
        target_info = normalize_target(keyword)
        target_info['rank'] = '0'
        
        probe_result = await run_probe_task(target_info, opts)
        
        if probe_result:
            http = probe_result.http or {}
            ssl = probe_result.ssl or {}
            dns = probe_result.dns or {}

            html = ""
            if probe_result.base_url and probe_result.base_url != "N/A":
                html = await fetch_html(probe_result.base_url)

            title = http.get("title", "N/A")
            server = http.get("server", "N/A")
            x_powered_by = http.get("xPoweredBy", "N/A")

            text_parts = []
            if title != "N/A":
                text_parts.append(f"Title: {title}")
            if server != "N/A":
                text_parts.append(f"Server: {server}")
            if x_powered_by != "N/A":
                text_parts.append(f"X_Powered_By: {x_powered_by}")
            body_text = clean_html(html)
            if body_text:
                text_parts.append(body_text)

            text_feature = " | ".join(text_parts) if text_parts else ""
            predicted_tags = model_service.predict(text_feature)
            if not text_feature:
                predicted_tags = ["基础探测(无内容)"]

            # IP from DNS or probe result
            ip = dns.get("a", "Unknown") if dns.get("a", "N/A") != "N/A" else "Unknown"

            # Tech stack detection from HTML + headers
            tech_stack = detect_tech_stack(html, http.get("server", ""), http.get("xPoweredBy", ""), http.get("contentType", ""))
            sec_headers = audit_security_headers(http)

            # Geo-IP lookup
            geo = await lookup_ip_geo(ip)

            # Insert into DB
            import json
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            node_id = str(uuid.uuid4())
            domain = probe_result.domain
            loc = geo["loc"]
            lat = geo["lat"]
            lng = geo["lng"]
            type_val = "normal"
            tags = ",".join(predicted_tags) if predicted_tags else "未分类"

            # Parse open_ports from CSV
            row_data = parse_csv_row(probe_result.csv_row)
            open_ports_str = row_data[8] if len(row_data) > 8 else "N/A"

            details_obj = {
                "open_ports": open_ports_str,
                "http_status": http.get("status", "N/A"),
                "title": http.get("title", "N/A"),
                "server": http.get("server", "N/A"),
                "x_powered_by": http.get("xPoweredBy", "N/A"),
                "waf": http.get("waf", "N/A"),
                "via": http.get("via", "N/A"),
                "set_cookie": http.get("setCookie", "N/A"),
                "hsts": http.get("hsts", "No"),
                "content_type": http.get("contentType", "N/A"),
                "ssl_issuer": ssl.get("issuer", "N/A"),
                "ssl_subject": ssl.get("subject", "N/A"),
                "ssl_valid_from": ssl.get("validFrom", "N/A"),
                "ssl_valid_to": ssl.get("validTo", "N/A"),
                "asn": geo["asn"],
                "dns_cname": dns.get("cname", "N/A"),
                "dns_mx": dns.get("mx", "N/A"),
                "dns_ns": dns.get("ns", "N/A"),
                "tech_stack": tech_stack,
                "security_headers": sec_headers,
            }
            details_json = json.dumps(details_obj, ensure_ascii=False)

            cursor.execute("INSERT OR REPLACE INTO nodes (id, domain, ip, loc, lat, lng, type, tags, details) VALUES (?,?,?,?,?,?,?,?,?)",
                           (node_id, domain, ip, loc, lat, lng, type_val, tags, details_json))
            conn.commit()
            conn.close()
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            node_id = str(uuid.uuid4())
            cursor.execute("INSERT OR REPLACE INTO nodes (id, domain, ip, loc, lat, lng, type, tags, details) VALUES (?,?,?,?,?,?,?,?,?)",
                           (node_id, keyword, "Unknown", "Unknown", 0.0, 0.0, "normal", "探测失败", "{}"))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"Probe task error: {e}")
    finally:
        probing_tasks.discard(keyword)

# 2. 编写提供给前端的查询接口
@app.get("/api/topology")
async def get_topology(keyword: str = ""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    status = "hit_cache"
    rows = []
    edge_rows = []
    
    # 支持根据搜索框的内容模糊查询
    if keyword:
        # Exact match first
        cursor.execute("SELECT * FROM nodes WHERE domain = ? OR ip = ?", (keyword, keyword))
        exact_rows = cursor.fetchall()
        
        if not exact_rows:
            if keyword in probing_tasks:
                status = "probing"
            else:
                probing_tasks.add(keyword)
                asyncio.create_task(run_probe_and_save(keyword))
                status = "probing"
                
        cursor.execute(
            "SELECT * FROM nodes WHERE domain LIKE ? OR ip LIKE ? LIMIT ?",
            (f"%{keyword}%", f"%{keyword}%", SEARCH_RESULT_LIMIT)
        )
        rows = cursor.fetchall()
        node_ids = [row[0] for row in rows]
        if node_ids:
            placeholders = ",".join("?" for _ in node_ids)
            cursor.execute(
                f"""
                SELECT * FROM edges
                WHERE source IN ({placeholders}) OR target IN ({placeholders})
                LIMIT ?
                """,
                (*node_ids, *node_ids, EDGE_LIMIT)
            )
            search_edges = cursor.fetchall()
            related_ids = []
            seen_ids = set(node_ids)
            for source, target, _edge_type in search_edges:
                for node_id in (source, target):
                    if node_id not in seen_ids:
                        related_ids.append(node_id)
                        seen_ids.add(node_id)
                    if len(related_ids) >= RELATED_NODE_LIMIT:
                        break
                if len(related_ids) >= RELATED_NODE_LIMIT:
                    break
            if related_ids:
                related_placeholders = ",".join("?" for _ in related_ids)
                cursor.execute(
                    f"SELECT * FROM nodes WHERE id IN ({related_placeholders})",
                    related_ids
                )
                rows.extend(cursor.fetchall())
            append_dynamic_related_rows(cursor, rows, RELATED_NODE_LIMIT)
    else:
        rows = balanced_overview_rows(cursor, DEFAULT_TOPOLOGY_LIMIT)
        
    nodes_result = []
    import json
    for row in rows:
        details_data = None
        if len(row) > 8 and row[8]:
            try:
                details_data = json.loads(row[8])
            except:
                pass
                
        asn = "Unknown"
        if details_data and details_data.get("asn"):
            asn = details_data["asn"]

        nodes_result.append({
            "id": row[0], "domain": row[1], "ip": row[2],
            "loc": row[3], "lat": row[4], "lng": row[5],
            "type": row[6],
            "tags": [{"name": t, "color": "text-cyan-400 bg-cyan-900"} for t in row[7].split(",")] if row[7] else [],
            "details": details_data,
            "asn": asn,
        })
        
    node_id_set = {node["id"] for node in nodes_result}
    if node_id_set:
        placeholders = ",".join("?" for _ in node_id_set)
        cursor.execute(
            f"""
            SELECT * FROM edges
            WHERE source IN ({placeholders}) AND target IN ({placeholders})
            LIMIT ?
            """,
            (*node_id_set, *node_id_set, EDGE_LIMIT)
        )
        edge_rows = cursor.fetchall()
    edges_result = []
    for row in edge_rows:
        edge_type = "asn" if row[2] == "ip" else row[2]
        if edge_type == "cdn":
            edge_type = "fingerprint"
        edges_result.append({
            "from": row[0], "to": row[1], "type": edge_type
        })
    edges_result = build_dynamic_edges(nodes_result, edges_result, EDGE_LIMIT)
    stats = get_global_stats(cursor)
        
    conn.close()
    
    # 按照前端需要的格式返回 JSON
    return {
        "status": status,
        "nodes": nodes_result,
        "edges": edges_result,
        "stats": stats,
    }

@app.on_event("startup")
async def startup_event():
    model_service.load_model()

# 放在所有路由之后挂载前端静态文件，实现一键启动
app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(BASE_DIR), "frontend"), html=True), name="static")

if __name__ == "__main__":
    print("后端服务已启动！API地址: http://127.0.0.1:8000/api/topology")
    uvicorn.run(app, host="127.0.0.1", port=8000)
