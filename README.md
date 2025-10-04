# Nulrix DirBuster (v0.2)  
  
Lightweight **directory & file brute-forcer** (Gobuster-lite) built with Python stdlib only.  
Perfect for **ethical web recon**, **CTFs**, and learning.

> Created by **Nulrix**. Education & authorized testing only.

## What's New (v0.2)
- `--insecure` to ignore TLS verification
- `--rate` global RPS limiter
- `--fingerprint` (md5 of first N bytes) + `--sample-bytes`
- `--min-bytes` / `--max-bytes` response size filters
- `--retries` for transient errors

## Quick Start
```bash
python3 dirbuster.py -u https://example.com/ -w wordlist.txt -x php,txt -c 64 -t 4.0
# Minimal (built-in small list)
python3 dirbuster.py -u https://example.com/
```

Follow redirects & export:
```bash
python3 dirbuster.py -u https://example.com/ -w wordlist.txt --follow -o out.json --csv out.csv
```

Aggressive but polite (rate limit + fingerprint + size filter):
```bash
python3 dirbuster.py -u https://example.com/ -w wordlist.txt --rate 50 --fingerprint --sample-bytes 1024 --min-bytes 100
```

## Arguments
```
-u, --url            Base URL (required), e.g. https://target.com/
-w, --wordlist       Path to wordlist file (optional; small default included)
-x, --extensions     Comma-separated extensions, e.g. php,txt,html
-c, --concurrency    Threads (default: 64)
-t, --timeout        Request timeout seconds (default: 4.0)
--status             Statuses to include (ranges ok). Default: 200-204,301,302,307,401,403
--exclude            Statuses to exclude (applied after --status)
--follow             Follow redirects (also prints Location when not following)
--no-color           Disable ANSI colors
-o, --out            Save JSON report
--csv                Save CSV report
--no-wildcard        Disable wildcard detection
--paths              Comma-separated custom paths (overrides wordlist)

# v0.2
--insecure           Ignore TLS verification (HTTPS)
--rate               Global requests per second (RPS) limit (0 = unlimited)
--fingerprint        Enable content fingerprinting (md5 of first N bytes)
--sample-bytes       Bytes to sample for fingerprinting/range GET (default: 512)
--min-bytes          Filter: minimum Content-Length
--max-bytes          Filter: maximum Content-Length
--retries            Retries per request on transient errors
```

## Notes
- Uses **HEAD** then a small **GET** (with `Range`) for precision/fingerprinting.
- **Wildcard detection** samples random paths; if status/length/(fingerprint) match, they're filtered.
- Respect legal/organizational policies. **Only test systems you own or have permission to test.**

## License
MIT © 2025 Nulrix
