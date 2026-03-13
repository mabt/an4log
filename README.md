# an4log v3.1.0

Analyseur de logs Apache/Nginx. Binaire unique statique, zero dependance, deploiement instantane.

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

# GeoIP + ASN (optionnel, pour pays et reseaux)
an4log setup-geoip
```

### Compiler depuis les sources

```bash
git clone https://github.com/mabt/an4log.git
cd an4log
CGO_ENABLED=0 go build -ldflags '-s -w' -o an4log .
```

## Utilisation

```bash
# Analyse complete
an4log -d /var/log/nginx/access.log

# Depuis stdin (pipe)
cat access.log | an4log -d - summary

# Multi-fichiers (glob)
an4log -d /var/log/nginx/*access*.log

# Top 20 codes HTTP
an4log -d access.log -n 20 status

# Menaces de la derniere heure
an4log -d access.log -since 1h threat

# Profiler une IP
an4log -ip 1.2.3.4 -d access.log

# Stats par jour / mois
an4log -d access*.log -group-by day
an4log -d access*.log -group-by month

# Rapport HTML interactif
an4log -d access.log -html rapport.html

# Export JSON / CSV
an4log -d access.log -json export.json
an4log -d access.log -csv export.csv

# Suggestions de blocage (iptables/fail2ban/ipset)
an4log -d access.log actions

# IPs brutes pour pipe vers iptables/ipset
an4log -d access.log actions -output-ips

# Exclure les bots
an4log -d access.log -exclude-bots
```

## Commandes disponibles

### Analyse generale
| Commande | Description |
|----------|-------------|
| `all` | Toutes les analyses (defaut) |
| `summary` | Dashboard rapide (stats + alertes) |
| `classify` | Repartition du trafic par categorie |
| `visitors` | Visiteurs uniques (IP + User-Agent) |

### Trafic
| Commande | Description |
|----------|-------------|
| `ip` | Top IPs par nombre de requetes |
| `ua` | Top User-Agents |
| `uri` | Top URIs (sans query string) |
| `prefix` | Top prefixes IP (xxx.xxx.*) |
| `status` | Top codes HTTP |
| `heavy` | Top IPs par volume transfere |
| `methods` | Repartition des methodes HTTP |
| `timeline` | Trafic par jour ou mois (avec `-group-by`) |
| `hour` | Repartition par heure |
| `minute` | Pics de trafic par minute |
| `slow` | Requetes les plus lentes |
| `response-time` | Temps de reponse par URI (p50, p95, p99) |
| `vhost` | Virtual hosts (auto-detecte) |
| `404` | Top URIs en erreur 404 |
| `403` | Top IPs bloquees (403) |
| `crawlers` | Bots/crawlers detectes |
| `suspect` | IPs suspectes (> seuil de requetes) |
| `empty-ua` | Requetes sans User-Agent |
| `burst` | Detection de burst par IP/minute |
| `post-flood` | Flood de requetes POST par IP |
| `countries` | Top pays par nombre de hits |
| `asn` | Top reseaux / ASN (OVH, AWS, Google...) |

### Securite
| Commande | Description |
|----------|-------------|
| `threat` | Vue combinee de toutes les menaces |
| `actions` | Suggestions iptables / fail2ban / ipset |
| `sql` | Tentatives d'injection SQL |
| `xss` | Tentatives XSS |
| `traversal` | Tentatives de path traversal |
| `scanners` | Detection de scanners (nikto, sqlmap...) |
| `wp-attack` | Attaques WordPress |

## Options

| Option | Description |
|--------|-------------|
| `-d FILE` | Fichier(s) log (glob ok, repeatable, `-` pour stdin) |
| `-n N` | Nombre de resultats (defaut: 10) |
| `-g PATH` | Chemin base GeoLite2-Country.mmdb |
| `-w FILE` | Fichier whitelist externe |
| `-c FILE` | Fichier de configuration |
| `-since` | Filtrer depuis: `30m`, `2h`, `1d`, `2026-03-09` |
| `-ip` | Filtrer / profiler une IP |
| `-group-by` | Grouper par `day` ou `month` |
| `-html FILE` | Generer un rapport HTML interactif |
| `-json FILE` | Exporter en JSON |
| `-csv FILE` | Exporter en CSV (une ligne par IP) |
| `-exclude-bots` | Exclure les bots connus |
| `-output-ips` | Sortie IPs brutes (pour pipe) |
| `-suspect-threshold N` | Seuil IPs suspectes (defaut: 500) |
| `-ua-threshold N` | Seuil IPs sans UA (defaut: 50) |
| `-burst-threshold N` | Seuil burst req/min (defaut: 30) |

## Rapport HTML

Le rapport HTML est autonome (CSS + JS inline) et inclut :
- KPIs (requetes, IPs, volume, bots, erreurs, menaces)
- Timeline interactive avec boutons **Jour / Mois / Tout**
- Classification du trafic (humain, paiement, monitoring, bots, SEO, IA)
- Trafic par heure (bar chart)
- Top IPs, URIs, codes HTTP (tableaux triables)
- Top pays (si GeoIP disponible)
- Securite (menaces, IPs a bannir)
- Bots et erreurs 404

## Detection

- **Menaces** : SQL injection, XSS, path traversal, WordPress, fichiers sensibles
- **Scanners** : nikto, sqlmap, nmap, nuclei, wpscan...
- **Classification UA** : paiement (Lyra, PayPal, Stripe...), monitoring (Uptime-Kuma, Sansec...), bots legitimes (Google, Bing...), SEO, IA
- **IPs protegees** : les IPs de paiement et monitoring ne sont jamais suggerees au ban
- **ASN** : identification du reseau source (OVH, AWS, Google, Cloudflare...)

## Configuration

Fichier `/etc/an4log/an4log.conf` ou `~/.an4log.conf` :

```ini
top_n = 10
suspect_threshold = 500
ua_threshold = 50
burst_threshold = 30
whitelist = 5.39.38.0/24, 5.22.211.82
geoip_db = /usr/share/GeoIP/GeoLite2-Country.mmdb
```

## Code retour

| Code | Signification |
|------|---------------|
| `0` | Aucune menace detectee |
| `1` | Menaces detectees |
| `2` | Erreur (fichier introuvable, format invalide) |

## Notes

- Binaire statique ~6 MB, aucune dependance runtime
- Lecture depuis stdin (`-d -`) pour piper depuis `tail`, `zcat`, etc.
- Auto-detection du format vhost (vhost:port IP ... vs IP ...)
- Temps de reponse: ajouter `%D` (Apache) ou `$request_time` (Nginx) en fin de log
- Les fichiers `*.error.log` sont automatiquement ignores
- La whitelist fail2ban (`/etc/fail2ban/jail.d/whitelist-ips.conf`) est chargee automatiquement
- Supporte les fichiers `.gz`
- Parsing single-pass optimise
