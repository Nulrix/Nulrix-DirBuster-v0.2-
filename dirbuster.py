#!/usr/bin/env python3
"""
Nulrix DirBuster v0.2 (Gobuster-lite)
Lightweight directory & file brute-forcer for ethical web recon.

New in v0.2:
- --insecure : ignore TLS verification
- --rate     : global requests-per-second rate limit
- --fingerprint / --sample-bytes : content hashing for better wildcard detection
- --min-bytes / --max-bytes : response size filters
- --retries  : transient error retries

Author: Nulrix
License: MIT
"""
from __future__ import annotations
import argparse
import concurrent.futures as cf
import csv
import http.client
import os
import random
import socket
import ssl
import string
import sys
import threading
import time
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple
from urllib.parse import urlparse, quote
import hashlib

# ---------------------- Colors ----------------------
class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; Bl = "\033[34m"; M = "\033[35m"; C = "\033[36m"; W = "\033[97m"; D = "\033[0m"

def color(s, c):
    if getattr(color, "disable", False):
        return s
    return f"{c}{s}{C.D}"

# ---------------------- Data models ----------------------
@dataclass
class Finding:
    path: str
    status: int
    length: Optional[int]
    redirected: Optional[str] = None
    fingerprint: Optional[str] = None  # md5 of first N bytes (optional)

@dataclass
class Report:
    base_url: str
    elapsed_ms: int
    findings: List[Finding]

# ---------------------- Rate Limiter ----------------------
class RateLimiter:
    """Simple global rate limiter (tokens/sec) shared across threads."""
    def __init__(self, rate: float):
        self.rate = float(rate)
        self.lock = threading.Lock()
        self.next_ts = 0.0
        if self.rate <= 0:
            self.enabled = False
        else:
            self.enabled = True
            self.interval = 1.0 / self.rate

    def acquire(self):
        if not self.enabled:
            return
        with self.lock:
            now = time.perf_counter()
            if self.next_ts <= 0:
                self.next_ts = now
            if now < self.next_ts:
                time.sleep(self.next_ts - now)
                now = time.perf_counter()
            self.next_ts = max(self.next_ts + self.interval, now)

# ---------------------- HTTP helpers ----------------------
def make_connection(parsed, timeout: float, insecure: bool):
    host = parsed.hostname
    port = parsed.port
    if parsed.scheme == "https":
        if insecure:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context()
        return http.client.HTTPSConnection(host, port or 443, timeout=timeout, context=ctx)
    else:
        return http.client.HTTPConnection(host, port or 80, timeout=timeout)

def request_once(parsed, path, timeout: float, follow: bool, insecure: bool, want_fingerprint: bool, sample_bytes: int, retries: int, rl: RateLimiter):
    """
    Returns (status, length, redirected_to|None, fingerprint|None)
    Uses HEAD first; falls back to small GET (Range) if needed.
    """
    target = path if path.startswith("/") else "/" + path
    attempt = 0
    while True:
        rl.acquire()
        conn = None
        try:
            conn = make_connection(parsed, timeout, insecure)
            conn.request("HEAD", target, headers={"User-Agent": "nulrix-dirbuster/0.2"})
            resp = conn.getresponse()
            status = resp.status
            length = resp.getheader("Content-Length")
            location = resp.getheader("Location")
            fp = None 

            # Fallback or fingerprinting via small GET
            need_get = (status >= 400 or length is None or want_fingerprint)
            if need_get:
                # Close and re-open for GET
                conn.close()
                rl.acquire()
                conn = make_connection(parsed, timeout, insecure)
                headers = {"User-Agent": "nulrix-dirbuster/0.2"}
                # Try to get a small slice
                if sample_bytes > 0:
                    headers["Range"] = f"bytes=0-{max(0, sample_bytes-1)}"
                conn.request("GET", target, headers=headers)
                resp = conn.getresponse()
                status = resp.status
                length = resp.getheader("Content-Length")
                location = resp.getheader("Location")
                if want_fingerprint:
                    try:
                        body = resp.read(sample_bytes)
                        fp = hashlib.md5(body).hexdigest()
                    except Exception:
                        fp = None
                else:
                    # Touch body minimally to close properly
                    _ = resp.read(0)

            if follow and location and status in (301,302,303,307,308):
                return status, int(length) if (length and str(length).isdigit()) else None, location, fp
            return status, int(length) if (length and str(length).isdigit()) else None, (location if location and not follow else None), fp

        except Exception:
            if attempt < retries:
                attempt += 1
                time.sleep(min(0.1 * attempt, 0.5))
                continue
            return None, None, None, None
        finally:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass

# ---------------------- Wildcard detection ----------------------
def detect_wildcard(parsed, timeout: float, insecure: bool, want_fingerprint: bool, sample_bytes: int, rl: RateLimiter) -> Optional[Tuple[int, Optional[int], Optional[str]]]:
    """
    Returns a baseline tuple (status, length, fingerprint) if three random paths yield identical tuple.
    """
    patterns = []
    for _ in range(3):
        rnd = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(24))
        status, length, _, fp = request_once(parsed, f"/{rnd}", timeout, follow=False, insecure=insecure, want_fingerprint=want_fingerprint, sample_bytes=sample_bytes, retries=1, rl=rl)
        if status is None:
            return None
        patterns.append((status, length, fp if want_fingerprint else None))
    if len(set(patterns)) == 1:
        return patterns[0]
    return None

# ---------------------- Core ----------------------
def load_wordlist(path: str) -> List[str]:
    items = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if not w or w.startswith("#"):
                continue
            items.append(w)
    return items

def build_paths(words: List[str], exts: List[str]) -> List[str]:
    paths = set()
    for w in words:
        wq = quote(w.strip("/"))
        paths.add("/" + wq)
        for ext in exts:
            ext = ext.lstrip(".")
            paths.add("/" + wq + "." + ext)
    return sorted(paths)

def parse_codes(spec: Optional[str]) -> Optional[set]:
    if not spec:
        return None
    out = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a,b = part.split("-",1)
            a,b = int(a), int(b)
            if a>b: a,b = b,a
            out.update(range(a,b+1))
        else:
            out.add(int(part))
    return out

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="nulrix-dirbuster",
        description="Nulrix DirBuster - lightweight directory brute-forcer (ethical use only)"
    )
    ap.add_argument("-u", "--url", required=True, help="Base URL, e.g. https://target.com/")
    ap.add_argument("-w", "--wordlist", default=None, help="Path to wordlist file")
    ap.add_argument("-x", "--extensions", default="", help="Comma-separated extensions, e.g. php,txt,html")
    ap.add_argument("-c", "--concurrency", type=int, default=64, help="Threads (default: 64)")
    ap.add_argument("-t", "--timeout", type=float, default=4.0, help="Request timeout seconds (default: 4.0)")
    ap.add_argument("--status", default="200-204,301,302,307,401,403", help="Statuses to include (ranges ok)")
    ap.add_argument("--exclude", default=None, help="Statuses to exclude (applied after --status)")
    ap.add_argument("--follow", action="store_true", help="Follow redirects (report Location)")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    ap.add_argument("-o", "--out", default=None, help="Save JSON report")
    ap.add_argument("--csv", default=None, help="Save CSV report")
    ap.add_argument("--no-wildcard", action="store_true", help="Disable wildcard detection")
    ap.add_argument("--paths", default=None, help="Comma-separated custom paths (overrides wordlist)")

    # v0.2 additions
    ap.add_argument("--insecure", action="store_true", help="Ignore TLS verification (HTTPS)")
    ap.add_argument("--rate", type=float, default=0.0, help="Global requests per second (RPS) limit (0 = unlimited)")
    ap.add_argument("--fingerprint", action="store_true", help="Enable content fingerprinting (md5 of first N bytes)")
    ap.add_argument("--sample-bytes", type=int, default=512, help="Bytes to sample for fingerprinting/range GET (default: 512)")
    ap.add_argument("--min-bytes", type=int, default=None, help="Filter: minimum Content-Length")
    ap.add_argument("--max-bytes", type=int, default=None, help="Filter: maximum Content-Length")
    ap.add_argument("--retries", type=int, default=1, help="Retries per request on transient errors")

    args = ap.parse_args(argv)
    color.disable = args.no_color or not sys.stdout.isatty()

    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print(color("Invalid URL. Example: https://example.com/", C.R))
        return 2

    # Prepare wordlist/paths
    if args.paths:
        words = [p.strip() for p in args.paths.split(",") if p.strip()]
    elif args.wordlist:
        if not os.path.exists(args.wordlist):
            print(color(f"Wordlist not found: {args.wordlist}", C.R))
            return 2
        words = load_wordlist(args.wordlist)
    else:
        words = ["admin","login","dashboard","test","server-status","robots.txt","sitemap.xml","backup","config","uploads","api","phpinfo"]
    exts = [e.strip() for e in args.extensions.split(",") if e.strip()]
    paths = build_paths(words, exts)

    include = parse_codes(args.status)
    exclude = parse_codes(args.exclude) or set()

    rl = RateLimiter(args.rate)

    # Wildcard baseline
    wildcard = None
    if not args.no_wildcard:
        wildcard = detect_wildcard(parsed, args.timeout, args.insecure, args.fingerprint, max(0, args.sample_bytes), rl)
        if wildcard:
            w_status, w_len, w_fp = wildcard
            w_desc = f"status={w_status}, len={w_len}"
            if args.fingerprint:
                w_desc += f", fp={w_fp}"
            print(color(f"[i] Wildcard detected: {w_desc}", C.Y))

    print(color("== Nulrix DirBuster v0.2 ==", C.M))
    print(f"Target: {parsed.scheme}://{parsed.netloc} | Paths: {len(paths)} | Threads: {args.concurrency} | Timeout: {args.timeout}s | RPS: {args.rate or 'unlimited'}")

    findings: List[Finding] = []
    lock = threading.Lock()
    start = time.perf_counter()

    def task(pth):
        status, length, location, fp = request_once(
            parsed, pth, args.timeout, args.follow, args.insecure,
            want_fingerprint=args.fingerprint, sample_bytes=max(0, args.sample_bytes),
            retries=max(0, args.retries), rl=rl
        )
        if status is None:
            return
        # Wildcard filter
        if wildcard:
            if (status, length, fp if args.fingerprint else None) == wildcard:
                return
        # Status filter
        if include and status not in include:
            return
        if status in exclude:
            return
        # Size filters
        if args.min_bytes is not None and (length is None or length < args.min_bytes):
            return
        if args.max_bytes is not None and (length is not None and length > args.max_bytes):
            return

        with lock:
            findings.append(Finding(path=pth, status=status, length=length, redirected=location, fingerprint=(fp if args.fingerprint else None)))
            loc = f" -> {location}" if location else ""
            meta = f" [{length}]" if length is not None else ""
            fp_txt = f" fp={fp}" if (args.fingerprint and fp) else ""
            print(f"{color('[+]', C.G)} {pth} {color(str(status), C.C)}{meta}{fp_txt}{loc}")

    with cf.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        list(ex.map(task, paths))

    elapsed = int((time.perf_counter() - start) * 1000)
    print(color(f"\nScan complete in {elapsed} ms. Hits: {len(findings)}", C.Bl))

    # Outputs
    if args.out:
        payload = {
            "base_url": f"{parsed.scheme}://{parsed.netloc}",
            "elapsed_ms": elapsed,
            "findings": [asdict(f) for f in findings],
        }
        with open(args.out, "w", encoding="utf-8") as f:
            import json
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(color(f"JSON saved to {args.out}", C.C))
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["path","status","length","redirected","fingerprint"])
            for fnd in findings:
                w.writerow([fnd.path, fnd.status, fnd.length if fnd.length is not None else "", fnd.redirected or "", fnd.fingerprint or ""])
        print(color(f"CSV saved to {args.csv}", C.C))

    return 0

if __name__ == "__main__":
    sys.exit(main())
