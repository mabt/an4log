# an4log v3.2.0

Apache/Nginx log analyzer. Single static binary, zero dependencies, instant deployment.

![an4log demo](demo.gif)

## Installation

```bash
# Linux x86_64
curl -Lo /usr/local/bin/an4log https://github.com/mabt/an4log/releases/latest/download/an4log-linux-amd64
chmod +x /usr/local/bin/an4log

# Linux ARM64 (Raspberry Pi, Oracle ARM...)
curl -Lo /usr/local/bin/an4log https://github.com/mabt/an4log/releases/latest/download/an4log-linux-arm64
chmod +x /usr/local/bin/an4log

# macOS Apple Silicon
curl -Lo /usr/local/bin/an4log https://github.com/mabt/an4log/releases/latest/download/an4log-darwin-arm64
chmod +x /usr/local/bin/an4log

# GeoIP + ASN (optional, for country and network data)
an4log setup-geoip
```

### Build from source

```bash
git clone https://github.com/mabt/an4log.git
cd an4log
CGO_ENABLED=0 go build -ldflags '-s -w' -o an4log .
```

## Usage

```bash
# Full analysis
an4log -d /var/log/nginx/access.log

# From stdin (pipe)
cat access.log | an4log -d - summary

# Multiple files (glob)
an4log -d /var/log/nginx/*access*.log

# Top 20 HTTP codes
an4log -d access.log -n 20 status

# Threats from the last hour
an4log -d access.log -since 1h threat

# Profile an IP
an4log -ip 1.2.3.4 -d access.log

# Stats by day / month
an4log -d access*.log -group-by day
an4log -d access*.log -group-by month

# Interactive HTML report
an4log -d access.log -html report.html

# JSON / CSV export
an4log -d access.log -json export.json
an4log -d access.log -csv export.csv

# Blocking suggestions (iptables/fail2ban/ipset)
an4log -d access.log actions

# Raw IPs for piping to iptables/ipset
an4log -d access.log actions -output-ips

# Exclude bots
an4log -d access.log -exclude-bots
```

## Available commands

### Overview
| Command | Description |
|---------|-------------|
| `all` | All analyses (default) |
| `summary` | Quick dashboard (stats + alerts) |
| `classify` | Traffic breakdown by category (human, bots, payment, monitoring, SEO, AI) |
| `visitors` | Unique visitors (IP + User-Agent) |
| `timeline` | Traffic by day or month (with `-group-by`) |

### Top N (traffic)
| Command | Description |
|---------|-------------|
| `ip` | Top IPs by request count |
| `uri` | Top URIs (without query string) |
| `ua` | Top User-Agents |
| `status` | Top HTTP status codes |
| `heavy` | Top IPs by transferred volume |
| `methods` | HTTP methods breakdown |
| `vhost` | Virtual hosts (auto-detected) |
| `countries` | Top countries by hits (GeoIP) |
| `asn` | Top networks / ASN (OVH, AWS, Google...) |

### Time-based
| Command | Description |
|---------|-------------|
| `hour` | Distribution by hour |
| `minute` | Traffic peaks per minute |
| `slow` | Slowest requests |
| `response-time` | Response time by URI (p50, p95, p99) |

### Suspicious behavior
| Command | Description |
|---------|-------------|
| `suspect` | Suspect IPs (above request threshold) |
| `burst` | Burst detection per IP/minute |
| `post-flood` | POST request flood per IP |
| `empty-ua` | Requests without User-Agent |
| `prefix` | Top IP prefixes (xxx.xxx.*) |
| `crawlers` | Detected bots/crawlers |
| `404` | Top 404 URIs |
| `403` | Top blocked IPs (403) |

### Security
| Command | Description |
|---------|-------------|
| `threat` | Combined view of all threats |
| `actions` | iptables / fail2ban / ipset suggestions (score >= 10) |
| `sql` | SQL injection attempts |
| `xss` | XSS attempts |
| `traversal` | Path traversal attempts (double `../` or sensitive targets) |
| `scanners` | Scanner detection (nikto, sqlmap...) |
| `wp-attack` | WordPress attacks (excludes wp-cron) |
| `webshell` | Webshell scan detection (txets.php, c99.php, r57.php...) |
| `malformed` | Malformed URLs (domain-in-path, e.g. `/example.com/wp-content/...`) |
| `storm-404` | 404 storm detection (burst of 404s per minute) |

## Options

| Option | Description |
|--------|-------------|
| `-d FILE` | Log file(s) (glob ok, repeatable, `-` for stdin) |
| `-n N` | Number of results (default: 10) |
| `-g PATH` | Path to GeoLite2-Country.mmdb |
| `-w FILE` | External whitelist file |
| `-c FILE` | Configuration file |
| `-since` | Filter since: `30m`, `2h`, `1d`, `2026-03-09` |
| `-ip` | Filter / profile an IP |
| `-group-by` | Group by `day` or `month` |
| `-html FILE` | Generate interactive HTML report |
| `-json FILE` | Export as JSON |
| `-csv FILE` | Export as CSV (one row per IP) |
| `-exclude-bots` | Exclude known bots |
| `-output-ips` | Raw IP output (for piping) |
| `-suspect-threshold N` | Suspect IPs threshold (default: 500) |
| `-ua-threshold N` | No UA IPs threshold (default: 50) |
| `-burst-threshold N` | Burst threshold req/min (default: 30) |

## HTML report

The HTML report is self-contained (inline CSS + JS) and includes:
- KPIs (requests, IPs, volume, bots, errors, threats)
- Interactive timeline with **Day / Month / All** buttons
- Traffic classification (human, payment, monitoring, bots, SEO, AI)
- Hourly traffic (bar chart)
- Top IPs, URIs, HTTP codes (sortable tables)
- Top countries (if GeoIP available)
- Security (threats, IPs to ban)
- Bots and 404 errors

## Detection

- **Threats**: SQL injection, XSS, path traversal (double `../` or sensitive targets), WordPress (excludes wp-cron), sensitive files (`/.env`, `.git/HEAD`, `.htaccess`...)
- **Webshell scans**: txets.php, c99.php, r57.php, alfashell.php, adminer.php...
- **Malformed URLs**: domain-in-path patterns (`/example.com/wp-content/...`) typically caused by bots stripping `https://`
- **404 storms**: burst of 404 errors per minute that can exhaust PHP-FPM workers
- **Scanners**: nikto, sqlmap, nmap, nuclei, wpscan...
- **Ban threshold**: only IPs with score >= 10 are suggested in `actions` (avoids false positives on isolated hits)
- **UA classification**: payment (Lyra, PayPal, Stripe...), monitoring (Uptime-Kuma, Sansec...), legitimate bots (Google, Bing...), SEO, AI
- **Protected IPs**: payment and monitoring IPs are never suggested for banning
- **ASN**: source network identification (OVH, AWS, Google, Cloudflare...)

## Configuration

File `/etc/an4log/an4log.conf` or `~/.an4log.conf`:

```ini
top_n = 10
suspect_threshold = 500
ua_threshold = 50
burst_threshold = 30
whitelist = 10.0.0.0/8, 192.168.1.1
geoip_db = /usr/share/GeoIP/GeoLite2-Country.mmdb
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No threats detected |
| `1` | Threats detected |
| `2` | Error (file not found, invalid format) |

## Notes

- Static binary ~10 MB, no runtime dependencies
- Reads from stdin (`-d -`) for piping from `tail`, `zcat`, etc.
- Auto-detects vhost format (vhost:port IP ... vs IP ...)
- Response time: add `%D` (Apache) or `$request_time` (Nginx) at end of log format
- `*.error.log` files are automatically ignored
- fail2ban whitelist (`/etc/fail2ban/jail.d/whitelist-ips.conf`) is loaded automatically
- Supports `.gz` files
- Optimized single-pass parsing
