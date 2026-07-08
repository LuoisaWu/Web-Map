from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Dict, List

from webcheck.http_probe import RequestOptions
from webcheck.probe import CSV_HEADER_V2, CSV_HEADER_V2_CHINA, GlobalOptions, normalize_target, run_probe_task, escape_csv


def _parse_ports(s: str) -> List[int]:
    out: List[int] = []
    for part in (s or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            n = int(part)
        except Exception:
            continue
        if 0 < n < 65536:
            out.append(n)
    seen = set()
    dedup = []
    for p in out:
        if p not in seen:
            seen.add(p)
            dedup.append(p)
    return dedup


def _load_targets(args, skip_domains: set = None) -> List[Dict[str, str]]:
    targets: List[Dict[str, str]] = []
    seen = set(skip_domains) if skip_domains else set()

    def add(line: str, rank: str) -> None:
        info = normalize_target(line)
        hostname = info.get("hostname") or ""
        if not hostname:
            return
        if hostname in seen:
            return
        seen.add(hostname)
        info["rank"] = rank
        targets.append(info)

    if args.target:
        add(args.target, "0")

    if args.file and os.path.exists(args.file):
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                for raw in f.read().splitlines():
                    line = raw.strip()
                    if not line:
                        continue
                    parts = line.split(",")
                    if len(parts) >= 2 and parts[0].isdigit():
                        add(parts[1].strip(), parts[0].strip())
                    else:
                        add(parts[0].strip(), "N/A")
        except Exception:
            pass

    if not sys.stdin.isatty():
        try:
            for raw in sys.stdin:
                line = raw.strip()
                if line:
                    add(line, "Stdin")
        except OSError:
            pass

    return targets


async def _writer(out_file: str, queue: asyncio.Queue, append: bool, header: str = CSV_HEADER_V2) -> None:
    mode = "a" if append else "w"
    with open(out_file, mode, encoding="utf-8", errors="ignore", newline="") as f:
        if not append:
            f.write(header)
            f.flush()
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                break
            f.write(item + "\n")
            f.flush()
            queue.task_done()


async def _jsonl_writer(out_file: str, queue: asyncio.Queue, append: bool) -> None:
    mode = "a" if append else "w"
    with open(out_file, mode, encoding="utf-8", errors="ignore", newline="") as f:
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                break
            f.write(item + "\n")
            f.flush()
            queue.task_done()


async def main_async() -> int:
    p = argparse.ArgumentParser(prog="xmap_probe.py", add_help=True)
    p.add_argument("-t", "--target", help="指定单个探测目标（URL 或 IP）")
    p.add_argument("-f", "--file", help="指定批量读取的文件路径（TXT 或 CSV）")
    p.add_argument("-c", "--concurrency", type=int, default=20, help="设置最大并发扫描数（默认 20）")
    p.add_argument("--ports", default="", help="自定义需要扫描的端口，用逗号分隔")
    p.add_argument("--timeout", type=int, default=15000, help="全局请求超时时间（毫秒）")
    p.add_argument("-o", "--out", default="", help="指定输出的 CSV 文件路径（默认输出到控制台）")
    p.add_argument("--out-china", dest="out_china", default="", help="指定专门输出中国网站结果的 CSV 文件路径")
    p.add_argument("--append", action="store_true", help="若输出文件已存在，则在末尾追加而不是覆盖")
    p.add_argument("--redirect-log", dest="redirect_log", default="", help="可选输出重定向链日志（JSONL）")
    p.add_argument("--host-header", dest="host_header", default="", help="强制指定 HTTP 请求的 Host 头")
    p.add_argument("--sni", default="", help="强制指定 TLS 握手时的 SNI")
    p.add_argument("--dns", default="", help="自定义 DNS 解析服务器（多个用逗号分隔；也可用环境变量 WEBMAP_DNS）")
    args = p.parse_args()

    concurrency = max(1, int(args.concurrency or 20))
    ports = _parse_ports(args.ports) if args.ports else [80, 443, 21, 22, 8080, 8443, 3306]
    timeout_ms = max(100, int(args.timeout or 15000))
    out_file = args.out.strip()
    out_china = args.out_china.strip()
    redirect_log = args.redirect_log.strip()
    append = bool(args.append)

    dns_resolvers = [x.strip() for x in (args.dns or "").split(",") if x.strip()] if args.dns else None

    req_opts = RequestOptions(timeout_ms=timeout_ms, max_redirects=3)
    global_opts = GlobalOptions(
        ports_to_scan=ports,
        port_timeout_ms=min(timeout_ms, 3000),
        sni=args.sni or "",
        host_header=args.host_header or "",
        request_opts=req_opts,
        dns_resolvers=dns_resolvers,
    )

    skip_domains = set()
    if append and out_file and os.path.exists(out_file):
        try:
            import csv
            with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                for row in reader:
                    if len(row) > 1:
                        skip_domains.add(row[1].strip())
        except Exception:
            pass

    targets = _load_targets(args, skip_domains)
    if not targets:
        print("[-] 没有找到任何有效目标。请使用 --target 或 --file，或通过管道输入。", file=sys.stderr)
        return 1

    if skip_domains:
        print(f"[*] 发现 {len(skip_domains)} 个已扫描目标，已自动跳过（断点续传模式）")

    if out_file:
        os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
        print(f"[+] 成功加载 {len(targets)} 个目标，开始 Xmap 流式并发探测 (并发数: {concurrency})...")
    else:
        sys.stdout.write(CSV_HEADER_V2)
        sys.stdout.flush()

    sem = asyncio.Semaphore(concurrency)
    completed = 0

    if out_file:
        queue: asyncio.Queue = asyncio.Queue()
        writer_task = asyncio.create_task(_writer(out_file, queue, append=append and os.path.exists(out_file)))
    else:
        queue = None
        writer_task = None

    if out_china:
        os.makedirs(os.path.dirname(out_china) or ".", exist_ok=True)
        china_queue: asyncio.Queue = asyncio.Queue()
        china_writer_task = asyncio.create_task(
            _writer(out_china, china_queue, append=append and os.path.exists(out_china), header=CSV_HEADER_V2_CHINA)
        )
    else:
        china_queue = None
        china_writer_task = None

    if redirect_log:
        os.makedirs(os.path.dirname(redirect_log) or ".", exist_ok=True)
        redirect_queue: asyncio.Queue = asyncio.Queue()
        redirect_writer_task = asyncio.create_task(
            _jsonl_writer(redirect_log, redirect_queue, append=append and os.path.exists(redirect_log))
        )
    else:
        redirect_queue = None
        redirect_writer_task = None

    async def run_one(tinfo: Dict[str, str]) -> None:
        nonlocal completed
        async with sem:
            try:
                r = await run_probe_task(tinfo, global_opts)
                if not r:
                    return
                row = r.csv_row
                if out_file:
                    await queue.put(row)
                else:
                    sys.stdout.write(row + "\n")
                    sys.stdout.flush()

                if r.is_china and china_queue is not None:
                    china_row = row + "," + escape_csv(r.icp)
                    await china_queue.put(china_row)

                if redirect_queue is not None:
                    item = {
                        "Rank": r.rank,
                        "Domain": r.domain,
                        "base_url": r.base_url,
                        "final_url": r.final_url,
                        "redirect_chain": r.redirect_chain,
                    }
                    await redirect_queue.put(json.dumps(item, ensure_ascii=False, separators=(",", ":")))
            finally:
                completed += 1
                if out_file and completed % 10 == 0:
                    sys.stdout.write(f"\r[*] 进度: {completed}/{len(targets)}")
                    sys.stdout.flush()

    tasks = [asyncio.create_task(run_one(t)) for t in targets]
    await asyncio.gather(*tasks, return_exceptions=False)

    if out_file:
        await queue.put(None)
        await queue.join()
        await writer_task
        sys.stdout.write(f"\n[+] 探测完成！结果已保存至: {out_file}\n")
        sys.stdout.flush()

    if china_writer_task is not None:
        await china_queue.put(None)
        await china_queue.join()
        await china_writer_task
        sys.stdout.write(f"[+] 中国网站筛选结果已保存至: {out_china}\n")
        sys.stdout.flush()

    if redirect_writer_task is not None:
        await redirect_queue.put(None)
        await redirect_queue.join()
        await redirect_writer_task

    return 0


def main() -> None:
    try:
        code = asyncio.run(main_async())
    except KeyboardInterrupt:
        code = 130
    raise SystemExit(code)


if __name__ == "__main__":
    main()
