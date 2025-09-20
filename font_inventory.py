#!/usr/bin/env python3
"""
Font Inventory Crawler (Free & Auditable)
-----------------------------------------
Discover publicly used fonts across your company's domains.

Features
- Static crawl (default): requests HTML/CSS, parses @font-face and url(...) in CSS
- Optional rendered crawl: Playwright-powered, captures network font requests
- Respects robots.txt
- De-duplicates by SHA256
- Extracts font name metadata (family, subfamily, full name, PostScript name) via fontTools
- Handles WOFF/WOFF2/TTF/OTF (WOFF2 requires 'brotli' for best compatibility)
- CSV + JSON outputs with per-domain and global summaries

Usage
------
python font_inventory.py domains.txt --out outdir
python font_inventory.py https://example.com https://sub.example.com --max-pages 300 --rendered

Requirements
------------
See requirements.txt generated alongside this script.

Notes
-----
- Use "--rendered" if sites heavily inject CSS via JS; it's slower and requires Playwright.
- For large estates, seed with a list of key domains and increase --max-pages / --concurrency as needed.
"""
import asyncio
import aiohttp
import async_timeout
# import ssl  # Not used, so removed
import argparse
import hashlib
import csv
import os
import re
import time
from urllib.parse import urljoin, urlparse
from urllib import robotparser

from bs4 import BeautifulSoup
import tinycss2
from fontTools.ttLib import TTFont
import io
import json

try:
    import tldextract
except ImportError:
    tldextract = None

# Optional rendered mode
PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

# ---------------------------
# Helpers
# ---------------------------

FONT_EXTENSIONS = ('.woff2', '.woff', '.ttf', '.otf')
CSS_MIME_HINTS = ('text/css', 'text/plain')

def normalize_domain(url: str) -> str:
    p = urlparse(url)
    host = p.hostname or ''
    return host.lower()

def same_reg_domain(url_a: str, url_b: str) -> bool:
    """Restrict crawl to same registrable domain if tldextract is present, else same host."""
    if not tldextract:
        return normalize_domain(url_a) == normalize_domain(url_b)
    a = tldextract.extract(url_a)
    b = tldextract.extract(url_b)
    return (a.registered_domain == b.registered_domain) and bool(a.registered_domain)

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def is_font_url(u: str) -> bool:
    return any(u.lower().split('?',1)[0].endswith(ext) for ext in FONT_EXTENSIONS)

def guess_is_css(content_type: str, url: str) -> bool:
    if content_type:
        for hint in CSS_MIME_HINTS:
            if hint in content_type:
                return True
    # fallback on extension
    path = urlparse(url).path.lower()
    return path.endswith('.css')

def extract_links_and_styles(base_url: str, html: str):
    soup = BeautifulSoup(html, 'lxml')
    links = []
    styles = []
    for link in soup.find_all('link', href=True):
        rel = (link.get('rel') or [''])[0].lower()
        href = link['href']
        if 'stylesheet' in rel or href.lower().endswith('.css'):
            links.append(urljoin(base_url, href))
    for style in soup.find_all('style'):
        if style.string:
            styles.append(style.string)
    return links, styles

def parse_css_for_fonts(css_text: str, base_url: str):
    urls = set()
    try:
        rules = tinycss2.parse_stylesheet(css_text, skip_comments=True, skip_whitespace=True)
        for r in rules:
            if r.type == 'at-rule' and r.lower_at_keyword == 'font-face':
                # extract url(...) tokens within the block
                content = tinycss2.serialize(r.content) if r.content else ''
                for m in re.finditer(r'url\(([^)]+)\)', content, flags=re.IGNORECASE):
                    raw = m.group(1).strip().strip('\'"')
                    if raw.startswith('data:'):
                        continue
                    absu = urljoin(base_url, raw)
                    if is_font_url(absu):
                        urls.add(absu)
            elif r.type in ('qualified-rule',):
                # general url(...) use
                content = tinycss2.serialize(r.prelude) + tinycss2.serialize(r.content or [])
                for m in re.finditer(r'url\(([^)]+)\)', content, flags=re.IGNORECASE):
                    raw = m.group(1).strip().strip('\'"')
                    if raw.startswith('data:'):
                        continue
                    absu = urljoin(base_url, raw)
                    if is_font_url(absu):
                        urls.add(absu)
    except Exception:
        # fall back to regex (best-effort)
        for m in re.finditer(r'url\(([^)]+)\)', css_text, flags=re.IGNORECASE):
            raw = m.group(1).strip().strip('\'"')
            if raw.startswith('data:'):
                continue
            absu = urljoin(base_url, raw)
            if is_font_url(absu):
                urls.add(absu)
    return urls

def read_font_names(font_bytes: bytes):
    meta = {
        "family": None,
        "subfamily": None,
        "full_name": None,
        "postscript_name": None,
        "version": None,
    }
    try:
        # TTFont can read from BytesIO; allow lazy loading to avoid full glyf parse
        with TTFont(io.BytesIO(font_bytes), lazy=True) as tt:
            name = tt['name']
            def get_name(nid):
                rec = name.getName(nameID=nid, platformID=3, platEncID=1) or name.getName(nameID=nid, platformID=1, platEncID=0)
                return str(rec) if rec else None
            meta["family"] = get_name(1)
            meta["subfamily"] = get_name(2)
            meta["full_name"] = get_name(4)
            meta["postscript_name"] = get_name(6)
            # version string (nameID=5) often includes foundry build info
            meta["version"] = get_name(5)
    except Exception:
        pass
    return meta

# ---------------------------
# Crawler
# ---------------------------

class RobotsCache:
    def __init__(self):
        self.cache = {}

    async def allowed(self, session: aiohttp.ClientSession, url: str, user_agent: str) -> bool:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        if robots_url not in self.cache:
            rp = robotparser.RobotFileParser()
            try:
                async with session.get(robots_url, timeout=15) as resp:
                    if resp.status == 200:
                        txt = await resp.text(errors='ignore')
                        rp.parse(txt.splitlines())
                    else:
                        rp.parse([])
            except Exception:
                rp.parse([])
            self.cache[robots_url] = rp
        return self.cache[robots_url].can_fetch(user_agent, url)

class FontInventory:
    def __init__(self):
        self.fonts_by_hash = {}   # hash -> {meta}
        self.fonts_by_url = {}    # url -> hash
        self.by_domain = {}       # domain -> set(font_hash)
        self.url_errors = {}      # url -> error string

    def add_font(self, domain: str, url: str, content: bytes):
        h = sha256_bytes(content)
        if h not in self.fonts_by_hash:
            meta = read_font_names(content)
            meta.update({"sha256": h, "byte_size": len(content)})
            self.fonts_by_hash[h] = meta
        self.fonts_by_url[url] = h
        self.by_domain.setdefault(domain, set()).add(h)

    def record_error(self, url: str, err: str):
        self.url_errors[url] = err

async def fetch(session, url, *, max_bytes=10_000_000):
    try:
        async with async_timeout.timeout(30):
            async with session.get(url, allow_redirects=True) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                data = await resp.read()
                if len(data) > max_bytes:
                    raise RuntimeError(f"Too large: {len(data)} bytes")
                return resp.headers.get('content-type',''), data
    except Exception as e:
        raise RuntimeError(str(e))

async def crawl_static(seeds, max_pages=200, concurrency=10, user_agent="FontInventoryBot/1.0"):
    connector = aiohttp.TCPConnector(limit=concurrency, ttl_dns_cache=300)
    robots = RobotsCache()
    inv = FontInventory()
    seen = set()
    queue = asyncio.Queue()
    for s in seeds:
        await queue.put(s)

    async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": user_agent}) as session:
        async def worker():
            nonlocal inv
            while True:
                try:
                    url = await queue.get()
                except Exception:
                    return
                if url in seen or len(seen) >= max_pages:
                    queue.task_done()
                    continue
                seen.add(url)
                try:
                    if not await robots.allowed(session, url, user_agent):
                        queue.task_done()
                        continue
                    ctype, body = await fetch(session, url)
                    # HTML page
                    if 'html' in ctype or urlparse(url).path.endswith('/') or url.endswith('.html'):
                        links, styles = extract_links_and_styles(url, body.decode('utf-8', errors='ignore'))
                        # enqueue same-domain http(s) links
                        for a in BeautifulSoup(body, 'lxml').find_all('a', href=True):
                            href = urljoin(url, a['href'])
                            if href.startswith('http') and same_reg_domain(seeds[0], href):
                                if href not in seen:
                                    await queue.put(href)
                        # parse external stylesheets
                        for css_url in links:
                            try:
                                ctype2, css_bytes = await fetch(session, css_url)
                                css_text = css_bytes.decode('utf-8', errors='ignore')
                                for furl in parse_css_for_fonts(css_text, css_url):
                                    try:
                                        _, fbytes = await fetch(session, furl)
                                        inv.add_font(normalize_domain(url), furl, fbytes)
                                    except Exception as fe:
                                        inv.record_error(furl, f"fetch-font: {fe}")
                            except Exception as ce:
                                inv.record_error(css_url, f"fetch-css: {ce}")
                        # parse inline styles
                        for css_text in styles:
                            for furl in parse_css_for_fonts(css_text, url):
                                try:
                                    _, fbytes = await fetch(session, furl)
                                    inv.add_font(normalize_domain(url), furl, fbytes)
                                except Exception as fe:
                                    inv.record_error(furl, f"fetch-font: {fe}")
                    # CSS file fetched directly
                    elif guess_is_css(ctype, url):
                        css_text = body.decode('utf-8', errors='ignore')
                        for furl in parse_css_for_fonts(css_text, url):
                            try:
                                _, fbytes = await fetch(session, furl)
                                inv.add_font(normalize_domain(url), furl, fbytes)
                            except Exception as fe:
                                inv.record_error(furl, f"fetch-font: {fe}")
                    # direct font URL (seeded)
                    elif is_font_url(url):
                        inv.add_font(normalize_domain(url), url, body)
                except Exception as e:
                    inv.record_error(url, f"fetch: {e}")
                finally:
                    queue.task_done()

        tasks = [asyncio.create_task(worker()) for _ in range(concurrency)]
        await queue.join()
        for t in tasks:
            t.cancel()
        return inv


async def crawl_rendered(seeds, max_pages=100, user_agent="FontInventoryBot/1.0"):
    if not PLAYWRIGHT_AVAILABLE:
        raise RuntimeError("Playwright is not installed. Run: pip install playwright && playwright install")
    robots = RobotsCache()
    inv = FontInventory()
    seen = set()
    queue = asyncio.Queue()
    for s in seeds:
        await queue.put(s)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(user_agent=user_agent)
        page = await context.new_page()

        async def process(url):
            if url in seen or len(seen) >= max_pages:
                return
            seen.add(url)
            # robots
            async with aiohttp.ClientSession() as session:
                if not await robots.allowed(session, url, user_agent):
                    return

            font_requests = []
            def on_request(req):
                try:
                    rurl = req.url
                    if is_font_url(rurl):
                        font_requests.append(rurl)
                except Exception:
                    pass

            page.on("request", on_request)
            try:
                await page.goto(url, wait_until="networkidle", timeout=30000)
                # de-dup and fetch fonts via aiohttp for bytes + hashing
                async with aiohttp.ClientSession(headers={"User-Agent": user_agent}) as s:
                    for rurl in set(font_requests):
                        try:
                            _, fbytes = await fetch(s, rurl)
                            inv.add_font(normalize_domain(url), rurl, fbytes)
                        except Exception as fe:
                            inv.record_error(rurl, f"fetch-font: {fe}")
                # enqueue links
                anchors = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                for href in anchors:
                    if href.startswith("http") and same_reg_domain(seeds[0], href):
                        await queue.put(href)
            except Exception as e:
                inv.record_error(url, f"render: {e}")
            finally:
                page.remove_listener("request", on_request)

        while not queue.empty():
            url = await queue.get()
            await process(url)
            queue.task_done()

        await browser.close()
        return inv
# ---------------------------
# Reporting
# ---------------------------

def write_reports(inv: 'FontInventory', outdir: str):
    os.makedirs(outdir, exist_ok=True)
    fonts_csv = os.path.join(outdir, "fonts.csv")
    domains_csv = os.path.join(outdir, "domains.csv")
    errors_csv = os.path.join(outdir, "errors.csv")
    fonts_json = os.path.join(outdir, "fonts.json")

    # fonts.csv
    with open(fonts_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sha256","family","subfamily","full_name","postscript_name","version","byte_size","example_url"])
        # choose an example url for each font hash
        example_for_hash = {}
        for url, h in inv.fonts_by_url.items():
            example_for_hash.setdefault(h, url)
        for h, meta in inv.fonts_by_hash.items():
            w.writerow([
                h,
                meta.get("family") or "",
                meta.get("subfamily") or "",
                meta.get("full_name") or "",
                meta.get("postscript_name") or "",
                meta.get("version") or "",
                meta.get("byte_size") or 0,
                example_for_hash.get(h, "")
            ])

    # domains.csv
    with open(domains_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain","font_count_unique","font_hashes"])
        for domain, hashes in sorted(inv.by_domain.items()):
            w.writerow([domain, len(hashes), ";".join(sorted(hashes))])

    # errors.csv
    with open(errors_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url","error"])
        for url, err in inv.url_errors.items():
            w.writerow([url, err])

    # fonts.json
    report = {
        "fonts": inv.fonts_by_hash,
        "by_url": inv.fonts_by_url,
        "by_domain": {k: sorted(list(v)) for k, v in inv.by_domain.items()},
        "errors": inv.url_errors
    }
    with open(fonts_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

def load_seeds(args_list):
    seeds = []
    for item in args_list:
        if os.path.isfile(item):
            with open(item, "r", encoding="utf-8") as f:
                for line in f:
                    u = line.strip()
                    if u:
                        seeds.append(u)
        else:
            seeds.append(item)
    # normalize to absolute http(s) URLs
    norm = []
    for u in seeds:
        if not u.startswith(("http://","https://")):
            u = "https://" + u.strip("/")
        norm.append(u)
    return norm

def main():
    ap = argparse.ArgumentParser(description="Inventory publicly used web fonts across domains.")
    ap.add_argument("seeds", nargs="+", help="Seed domains/URLs or a .txt file with one domain per line")
    ap.add_argument("--out", default="font-inventory-out", help="Output directory")
    ap.add_argument("--max-pages", type=int, default=200, help="Max pages to visit (per crawl)")
    ap.add_argument("--concurrency", type=int, default=10, help="Concurrent fetches (static mode)")
    ap.add_argument("--rendered", action="store_true", help="Use Playwright to capture JS-injected font requests")
    ap.add_argument("--user-agent", default="FontInventoryBot/1.0", help="Crawler user-agent")
    args = ap.parse_args()

    seeds = load_seeds(args.seeds)
    os.makedirs(args.out, exist_ok=True)

    t0 = time.time()
    t0 = time.time()
    if args.rendered:
        inv = asyncio.run(crawl_rendered(seeds, max_pages=args.max_pages, user_agent=args.user_agent))
    else:
        inv = asyncio.run(crawl_static(seeds, max_pages=args.max_pages, concurrency=args.concurrency, user_agent=args.user_agent))
    write_reports(inv, args.out)
    dt = time.time() - t0
    print(f"[OK] Scanned {len(inv.by_domain)} domains, found {len(inv.fonts_by_hash)} unique fonts in {dt:.1f}s")
    print(f"Outputs: {args.out}/fonts.csv, {args.out}/domains.csv, {args.out}/errors.csv, {args.out}/fonts.json")
if __name__ == "__main__":
    main()
