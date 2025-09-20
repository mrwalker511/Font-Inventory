# Font Inventory

Font Inventory is a free, auditable crawler that discovers the web fonts your organization serves across public domains. It outputs CSV and JSON so you can reconcile usage with your font licenses.

## What it does

- Crawls sites and parses HTML/CSS to find `@font-face` declarations and `url(...)` references.
- Optionally renders pages in a headless browser to capture fonts loaded dynamically by JavaScript (SPA/React/Next.js, etc.).
- Downloads font binaries (WOFF/WOFF2/TTF/OTF), reads name tables via fontTools, and de-duplicates by SHA-256 hash.
- Respects `robots.txt`.
- Produces four reports: `fonts.csv`, `domains.csv`, `errors.csv`, and `fonts.json`.

## Why it’s different

- Transparent, self-hosted, and auditable (no data leaves your environment).
- Binary-level fingerprinting (hashing) avoids false positives when files are renamed or subset.
- Real font metadata (family, subfamily, full name, PostScript name, version).
- Two crawl modes:
  - **Static**: fast HTML/CSS parsing.
  - **Rendered**: Playwright-powered network capture for JS-injected fonts.

## Repository layout

## font-inventory/
## ├── font_inventory.py # main crawler
## ├── tools/
## │ └── scan.py # build live seed list from registrar CSV (Step 0)
## ├── examples/
## │ ├── domains.txt
## │ └── sample-output/
## ├── requirements.txt
## ├── README.md
## ├── LICENSE
## └── .gitignore

## Installation

### Prerequisites

- Python 3.10+ recommended
- Internet access to crawl your sites
- Optional for rendered mode: Playwright (Chromium)

### Linux/macOS

```bash
git clone https://github.com/your-org/font-inventory.git
cd font-inventory

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
# For rendered mode:
# pip install playwright
# playwright install

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
# For rendered mode:
# pip install playwright
# python -m playwright install

### Windows

If activation fails on Windows, allow scripts once: