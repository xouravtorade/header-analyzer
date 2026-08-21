# Header Analyzer

A small Python CLI that checks a website's HTTP response for commonly recommended security headers.

## Progress

**52/100 security tools**

## Features

- Checks six defensive HTTP security headers
- Follows redirects and reports the final URL and status
- Uses a bounded request timeout
- Supports an explicit `--insecure` option for controlled lab environments

## Setup

```bash
python3 -m pip install requests
```

## Usage

```bash
python3 header_analyzer.py https://example.com
python3 header_analyzer.py https://localhost:8443 --insecure
```

Only scan systems you own or have explicit permission to test. See [DISCLAIMER.md](DISCLAIMER.md) for scope and safety guidance.

## License

Released under the MIT License. See [LICENSE](LICENSE).
