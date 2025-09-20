#!/usr/bin/env python3
import os
import sys
import time
import random
import socket
import argparse
import pandas as pd
import requests
from requests.exceptions import RequestException
import dns.resolver

# --------- Defaults (can be overridden via CLI) ----------
DEFAULT_CSV_PATH = "domains.csv"
DEFAULT_OUTPUT_CSV = "domains_results.csv"
DEFAULT_OUTPUT_TXT = "domains_live_seeds.txt"

# Rate limiting / reliability knobs
BASE_SLEEP = 0.25         # seconds between domains
JITTER_RANGE = 0.25       # extra random delay added to BASE_SLEEP
COOLDOWN_EVERY = 100      # after this many domains, take a longer nap
COOLDOWN_SECS = 10        # cool-down duration

# DNS behavior
DNS_TIMEOUT = 3
DNS_LIFETIME = 5
MAX_DNS_RETRIES = 3       # per domain
BACKOFF_BASE = 0.1        # base for 2^(attempt-1) * BACKOFF_BASE (seconds)
BACKOFF_JITTER = 0.05     # extra random jitter on backoff

# HTTP behavior
HTTP_TIMEOUT = 6
USER_AGENT = "DomainProbeBot/1.0"

# ---------------------------------------------------------

def detect_domain_column(df: pd.DataFrame) -> str:
    candidates = [c for c in df.columns if "domain" in c.lower()]
    if candidates:
        return candidates[0]
    name_candidates = [c for c in df.columns if "name" in c.lower()]
    if name_candidates:
        return name_candidates[0]
    return df.columns[0]

def load_domains(csv_path: str):
    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    col = detect_domain_column(df)
    domains = (
        df[col]
        .astype(str)
        .str.strip()
        .str.lower()
        .replace({"": None})
        .dropna()
        .unique()
        .tolist()
    )
    print(f"Found {len(domains)} unique domains in column '{col}'")
    return domains

# resolver & HTTP session (module-level singletons)
resolver = dns.resolver.Resolver()
session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

def query_dns_once(domain: str) -> dict:
    recs = {"a": [], "aaaa": [], "cname": []}
    # A
    try:
        answers = resolver.resolve(domain, "A")
        recs["a"] = [r.to_text() for r in answers]
    except Exception:
        pass
    # AAAA
    try:
        answers = resolver.resolve(domain, "AAAA")
        recs["aaaa"] = [r.to_text() for r in answers]
    except Exception:
        pass
    # CNAME
    try:
        answers = resolver.resolve(domain, "CNAME")
        recs["cname"] = [r.to_text().rstrip(".") for r in answers]
    except Exception:
        pass

    # socket fallback if nothing
    if not (recs["a"] or recs["aaaa"] or recs["cname"]):
        try:
            infos = socket.getaddrinfo(domain, None)
            addrs = list({i[4][0] for i in infos})
            recs["a"] = addrs
        except Exception:
            pass
    return recs

def query_dns_with_retries(domain: str, max_retries: int, backoff_base: float, backoff_jitter: float) -> dict:
    last_recs = {"a": [], "aaaa": [], "cname": []}
    for attempt in range(1, max_retries + 1):
        last_recs = query_dns_once(domain)
        if last_recs["a"] or last_recs["aaaa"] or last_recs["cname"]:
            return last_recs
        # backoff + jitter
        time.sleep((2 ** (attempt - 1)) * backoff_base + random.random() * backoff_jitter)
    return last_recs

def probe_http(domain: str, timeout: int) -> dict:
    statuses = {"https_status": None, "http_status": None, "https_ok": False, "http_ok": False}
    for proto in ("https", "http"):
        url = f"{proto}://{domain}"
        try:
            # HEAD first
            r = session.head(url, allow_redirects=True, timeout=timeout)
            statuses[f"{proto}_status"] = r.status_code
            statuses[f"{proto}_ok"] = (r.status_code < 400)
            if statuses[f"{proto}_ok"]:
                continue
        except RequestException:
            pass
        # GET fallback
        try:
            r = session.get(url, allow_redirects=True, timeout=timeout)
            statuses[f"{proto}_status"] = r.status_code
            statuses[f"{proto}_ok"] = (r.status_code < 400)
        except RequestException:
            statuses[f"{proto}_status"] = None
            statuses[f"{proto}_ok"] = False
    return statuses

def main():
    ap = argparse.ArgumentParser(description="DNS + HTTP probe for a list of domains from GoDaddy export")
    ap.add_argument("--csv", default=DEFAULT_CSV_PATH, help="Path to input CSV (GoDaddy export)")
    ap.add_argument("--out-csv", default=DEFAULT_OUTPUT_CSV, help="Path to results CSV")
    ap.add_argument("--out-seeds", default=DEFAULT_OUTPUT_TXT, help="Path to domains seeds txt")

    ap.add_argument("--base-sleep", type=float, default=BASE_SLEEP, help="Base sleep between domains")
    ap.add_argument("--jitter", type=float, default=JITTER_RANGE, help="Random jitter added to base sleep")
    ap.add_argument("--cooldown-every", type=int, default=COOLDOWN_EVERY, help="Add a cool-down after N domains (0 to disable)")
    ap.add_argument("--cooldown", type=float, default=COOLDOWN_SECS, help="Cool-down seconds")

    ap.add_argument("--dns-timeout", type=float, default=DNS_TIMEOUT, help="dnspython per-query timeout")
    ap.add_argument("--dns-lifetime", type=float, default=DNS_LIFETIME, help="dnspython overall lifetime")
    ap.add_argument("--dns-retries", type=int, default=MAX_DNS_RETRIES, help="DNS retry attempts per domain")
    ap.add_argument("--backoff-base", type=float, default=BACKOFF_BASE, help="Retry backoff base (seconds)")
    ap.add_argument("--backoff-jitter", type=float, default=BACKOFF_JITTER, help="Retry backoff jitter (seconds)")

    ap.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT, help="HTTP timeout (seconds)")
    args = ap.parse_args()

    # Ensure output dirs exist
    for p in (args.out_csv, args.out_seeds):
        d = os.path.dirname(os.path.abspath(p))
        if d:
            os.makedirs(d, exist_ok=True)

    # Apply resolver settings
    resolver.timeout = args.dns_timeout
    resolver.lifetime = args.dns_lifetime

    domains = load_domains(args.csv)
    results = []
    start = time.time()

    for i, d in enumerate(domains, 1):
        print(f"[{i}/{len(domains)}] probing {d}")

        recs = query_dns_with_retries(
            d,
            max_retries=args.dns_retries,
            backoff_base=args.backoff_base,
            backoff_jitter=args.backoff_jitter
        )
        resolves = bool(recs["a"] or recs["aaaa"] or recs["cname"])
        http = probe_http(d, timeout=int(args.http_timeout)) if resolves else {
            "https_status": None, "http_status": None, "https_ok": False, "http_ok": False
        }

        results.append({
            "domain": d,
            "a_records": ";".join(recs["a"]),
            "aaaa_records": ";".join(recs["aaaa"]),
            "cname": ";".join(recs["cname"]),
            "resolves": resolves,
            "https_status": http.get("https_status"),
            "http_status": http.get("http_status"),
            "https_ok": http.get("https_ok"),
            "http_ok": http.get("http_ok")
        })

        # polite sleep with jitter
        sleep_time = args.base_sleep + random.random() * args.jitter
        if not resolves:
            sleep_time += 0.25
        time.sleep(sleep_time)

        # periodic cool-down
        if args.cooldown_every and (i % args.cooldown_every == 0):
            print(f"Cooling down for {args.cooldown}s...")
            time.sleep(args.cooldown)

    # write outputs
    df_out = pd.DataFrame(results)
    df_out.to_csv(args.out_csv, index=False)

    seeds = []
    for _, row in df_out.iterrows():
        d = row["domain"]
        if row["https_ok"]:
            seeds.append(f"https://{d}")
        elif row["http_ok"]:
            seeds.append(f"http://{d}")
        elif row["resolves"]:
            seeds.append(f"https://{d}")
    seeds = list(dict.fromkeys(seeds))

    with open(args.out_seeds, "w", encoding="utf-8") as fh:
        fh.write("\n".join(seeds))

    elapsed = time.time() - start
    print(f"\nWrote results CSV: {args.out_csv}")
    print(f"Wrote seeds file: {args.out_seeds} ({len(seeds)} entries)")
    print(f"Done in {elapsed:.1f}s")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        sys.exit(130)
