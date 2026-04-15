package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	os.Exit(run())
}

func run() int {
	initColors()

	var files stringSlice
	var topN int
	var geoipDB, whitelistFile, configFile string
	var since, filterIP, groupBy, htmlFile string
	var jsonFile, csvFile string
	var excludeBots, outputIPs, showVersion bool
	var suspectThreshold, uaThreshold, burstThreshold int

	flag.Var(&files, "d", "Log file(s) (glob ok, repeatable, - for stdin)")
	flag.IntVar(&topN, "n", 0, "Number of results (default: 10)")
	flag.StringVar(&geoipDB, "g", "", "Path to GeoLite2-Country.mmdb")
	flag.StringVar(&whitelistFile, "w", "", "External whitelist file")
	flag.StringVar(&configFile, "c", "", "Configuration file")
	flag.StringVar(&since, "since", "", "Filter since: 30m, 2h, 1d, 2026-03-09")
	flag.StringVar(&filterIP, "ip", "", "Filter / profile an IP")
	flag.BoolVar(&excludeBots, "exclude-bots", false, "Exclude known bots")
	flag.BoolVar(&outputIPs, "output-ips", false, "Raw IP output (for piping)")
	flag.StringVar(&groupBy, "group-by", "", "Group by day or month")
	flag.StringVar(&htmlFile, "html", "", "Generate HTML report")
	flag.StringVar(&jsonFile, "json", "", "Export as JSON")
	flag.StringVar(&csvFile, "csv", "", "Export as CSV")
	flag.IntVar(&suspectThreshold, "suspect-threshold", 0, "Suspect IPs threshold")
	flag.IntVar(&uaThreshold, "ua-threshold", 0, "No UA IPs threshold")
	flag.IntVar(&burstThreshold, "burst-threshold", 0, "Burst threshold req/min")
	flag.BoolVar(&showVersion, "v", false, "Show version")
	flag.BoolVar(&showVersion, "version", false, "Show version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "an4log v%s - Apache/Nginx log analyzer\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: an4log -d FILE [options] [COMMANDE]\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Commands:
  all, summary, classify, visitors, vhost, response-time, asn,
  ip, ua, uri, prefix, status, heavy, methods, timeline, hour, minute,
  slow, 404, 403, crawlers, suspect, empty-ua, burst, threat, actions,
  sql, xss, traversal, scanners, wp-attack, webshell, post-flood,
  malformed, storm-404, countries, setup-geoip

Examples:
  an4log -d /var/log/apache2/access.log
  an4log -d access.log -n 20 status
  an4log -d access.log -since 1h threat
  an4log -d access.log -ip 1.2.3.4
  an4log -d access.log actions -output-ips
  an4log -d access.log -html rapport.html
  an4log -d access.log -json export.json
  an4log -d access.log -csv export.csv
  cat access.log | an4log -d - summary
  an4log -d access*.log -group-by day
`)
	}

	flag.Parse()

	if showVersion {
		fmt.Printf("an4log v%s\n", version)
		return 0
	}

	// Parse remaining args for command, extra files, and late flags
	command := "all"
	validCmds := map[string]bool{
		"all": true, "summary": true, "classify": true, "visitors": true, "vhost": true,
		"response-time": true, "asn": true,
		"ip": true, "ua": true, "uri": true, "prefix": true, "status": true,
		"heavy": true, "methods": true, "timeline": true, "hour": true, "minute": true,
		"slow": true, "404": true, "403": true, "crawlers": true, "suspect": true,
		"empty-ua": true, "burst": true, "threat": true, "actions": true, "sql": true,
		"xss": true, "traversal": true, "scanners": true, "wp-attack": true,
		"post-flood": true, "countries": true, "setup-geoip": true, "ip-profile": true,
		"webshell": true, "malformed": true, "storm-404": true,
	}
	// Late flags: flags that appear after positional args (without -d)
	lateFlags := map[string]bool{
		"-since": true, "-ip": true, "-n": true, "-g": true, "-w": true, "-c": true,
		"-group-by": true, "-html": true, "-json": true, "-csv": true,
		"-exclude-bots": true, "-output-ips": true,
		"-suspect-threshold": true, "-ua-threshold": true, "-burst-threshold": true,
	}
	remaining := flag.Args()
	var extraFiles []string
	for i := 0; i < len(remaining); i++ {
		arg := remaining[i]
		if validCmds[arg] {
			command = arg
		} else if lateFlags[arg] {
			// Handle late flags
			switch arg {
			case "-exclude-bots":
				excludeBots = true
			case "-output-ips":
				outputIPs = true
			default:
				if i+1 < len(remaining) {
					i++
					val := remaining[i]
					switch arg {
					case "-since":
						since = val
					case "-ip":
						filterIP = val
					case "-n":
						fmt.Sscanf(val, "%d", &topN)
					case "-g":
						geoipDB = val
					case "-w":
						whitelistFile = val
					case "-c":
						configFile = val
					case "-group-by":
						groupBy = val
					case "-html":
						htmlFile = val
					case "-json":
						jsonFile = val
					case "-csv":
						csvFile = val
					case "-suspect-threshold":
						fmt.Sscanf(val, "%d", &suspectThreshold)
					case "-ua-threshold":
						fmt.Sscanf(val, "%d", &uaThreshold)
					case "-burst-threshold":
						fmt.Sscanf(val, "%d", &burstThreshold)
					}
				} else {
					warn(fmt.Sprintf("Option %s missing value", arg))
				}
			}
		} else {
			extraFiles = append(extraFiles, arg)
		}
	}
	files = append(files, extraFiles...)

	// Config
	cfg := loadConfig(configFile)
	if topN > 0 {
		cfg["top_n"] = topN
	}
	if geoipDB != "" {
		cfg["geoip_db"] = geoipDB
	}
	if suspectThreshold > 0 {
		cfg["suspect_threshold"] = suspectThreshold
	}
	if uaThreshold > 0 {
		cfg["ua_threshold"] = uaThreshold
	}
	if burstThreshold > 0 {
		cfg["burst_threshold"] = burstThreshold
	}
	if outputIPs {
		disableColors()
	}

	// GeoIP auto-detect
	if cfgStr(cfg, "geoip_db", "") == "" {
		cfg["geoip_db"] = findGeoIPDB("")
	}

	// setup-geoip
	if command == "setup-geoip" {
		cmdSetupGeoIP(cfg)
		return 0
	}

	// Validate -d
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "Error: log file required (-d <file>)\n")
		flag.Usage()
		return 2
	}

	// Resolve files (stdin = "-")
	isStdin := len(files) == 1 && (files[0] == "-" || files[0] == "/dev/stdin")
	var resolved []string
	if isStdin {
		resolved = []string{"-"}
	} else {
		resolved = resolveFiles(files)
		if len(resolved) == 0 {
			fmt.Fprintf(os.Stderr, "%sError: no log files found%s\n", cRed, cReset)
			return 2
		}
		if !validateFormat(resolved) {
			return 2
		}
	}

	// Header
	if !outputIPs {
		fmt.Printf("%san4log v%s%s\n", cBold, version, cReset)
		if len(resolved) == 1 {
			fmt.Printf("File: %s%s%s\n", cCyan, resolved[0], cReset)
		} else {
			fmt.Printf("Files: %s%d%s files\n", cBold, len(resolved), cReset)
			limit := 5
			if len(resolved) < limit {
				limit = len(resolved)
			}
			for _, f := range resolved[:limit] {
				fmt.Printf("  %s%s%s\n", cCyan, f, cReset)
			}
			if len(resolved) > 5 {
				fmt.Printf("  ... +%d more\n", len(resolved)-5)
			}
		}
	}

	// IP profile shortcut
	if filterIP != "" && command == "all" {
		command = "ip-profile"
	}

	// Parse
	t0 := time.Now()
	data := parseLog(resolved, cfg, since, filterIP, excludeBots, groupBy)
	elapsed := time.Since(t0).Seconds()

	if !outputIPs {
		var sizeBytes int64
		if !isStdin {
			for _, f := range resolved {
				if info, err := os.Stat(f); err == nil {
					sizeBytes += info.Size()
				}
			}
		}
		sizeStr := fmtSize(sizeBytes)
		if isStdin {
			sizeStr = "stdin"
		}
		fmt.Printf("Lines: %s%s%s | Size: %s%s%s | Parse: %s%.2fs%s\n",
			cBold, fmtComma(data.Total), cReset,
			cBold, sizeStr, cReset,
			cBold, elapsed, cReset)
		if data.ParseErrors > 0 {
			warn(fmt.Sprintf("%d unparsed line(s)", data.ParseErrors))
		}
		if since != "" {
			fmt.Printf("Filter: %s--since %s%s\n", cYellow, since, cReset)
		}
		if filterIP != "" {
			fmt.Printf("IP filter: %s%s%s\n", cYellow, filterIP, cReset)
		}
		if excludeBots {
			fmt.Printf("Filter: %s--exclude-bots%s\n", cYellow, cReset)
		}
	}

	// Whitelist
	wlRaw, wlNets := loadWhitelist(cfg, whitelistFile)

	// GeoIP
	geo := make(map[string]string)
	geoFull := make(map[string][2]string)
	if command == "actions" || command == "threat" || htmlFile != "" {
		dbPath := cfgStr(cfg, "geoip_db", "")
		if htmlFile != "" {
			geoFull = resolveGeoIPFull(data.IPCounts, dbPath)
			for ip, info := range geoFull {
				geo[ip] = info[0]
			}
		} else {
			ips := make(map[string]bool)
			for ip := range data.IPThreats {
				ips[ip] = true
			}
			thresh := cfgInt(cfg, "suspect_threshold", 500)
			for ip, c := range data.IPCounts {
				if c > thresh {
					ips[ip] = true
				}
			}
			geo = resolveGeoIP(ips, dbPath)
		}
	}

	// HTML report
	if htmlFile != "" {
		html := generateHTMLReport(data, cfg, resolved, elapsed, geo, wlRaw, wlNets, geoFull)
		if err := os.WriteFile(htmlFile, []byte(html), 0644); err != nil {
			warn(fmt.Sprintf("Error writing HTML: %v", err))
		} else {
			fmt.Printf("%sHTML report generated: %s%s\n", cGreen, htmlFile, cReset)
		}
		if !outputIPs && command == "all" {
			if len(data.ThreatCounts) > 0 {
				return 1
			}
			return 0
		}
	}

	// JSON export
	if jsonFile != "" {
		if err := writeExport(jsonFile, "json", data, cfg); err != nil {
			warn(fmt.Sprintf("Error writing JSON: %v", err))
		} else {
			fmt.Printf("%sExport JSON: %s%s\n", cGreen, jsonFile, cReset)
		}
	}

	// CSV export
	if csvFile != "" {
		ensureProfileData(data)
		if err := writeExport(csvFile, "csv", data, cfg); err != nil {
			warn(fmt.Sprintf("Error writing CSV: %v", err))
		} else {
			fmt.Printf("%sExport CSV: %s%s\n", cGreen, csvFile, cReset)
		}
	}

	// Dispatch
	ctx := &CmdCtx{
		Data: data, Cfg: cfg, Geo: geo, GeoFull: geoFull,
		WLRaw: wlRaw, WLNets: wlNets, FilterIP: filterIP, OutputIPs: outputIPs,
	}
	switch command {
	case "all":
		cmdAll(ctx)
	case "summary":
		cmdSummary(data, cfg)
	case "classify":
		cmdClassify(data, cfg)
	case "ip":
		cmdIP(data, cfg)
	case "ua":
		cmdUA(data, cfg)
	case "uri":
		cmdURI(data, cfg)
	case "prefix":
		cmdPrefix(data, cfg)
	case "status":
		cmdStatus(data, cfg)
	case "heavy":
		cmdHeavy(data, cfg)
	case "methods":
		cmdMethods(data, cfg)
	case "timeline":
		cmdTimeline(data, cfg)
	case "hour":
		cmdHour(data, cfg)
	case "minute":
		cmdMinute(data, cfg)
	case "slow":
		cmdSlow(data, cfg)
	case "404":
		cmd404(data, cfg)
	case "403":
		cmd403(data, cfg)
	case "crawlers":
		cmdCrawlers(data, cfg)
	case "suspect":
		cmdSuspect(data, cfg)
	case "empty-ua":
		cmdEmptyUA(data, cfg)
	case "burst":
		cmdBurst(data, cfg)
	case "threat":
		cmdThreat(data, cfg)
	case "actions":
		cmdActions(data, cfg, geo, wlRaw, wlNets, outputIPs)
	case "sql":
		cmdSQL(data, cfg)
	case "xss":
		cmdXSS(data, cfg)
	case "traversal":
		cmdTraversal(data, cfg)
	case "scanners":
		cmdScanners(data, cfg)
	case "wp-attack":
		cmdWPAttack(data, cfg)
	case "post-flood":
		cmdPostFlood(data, cfg)
	case "countries":
		cmdCountries(data, cfg)
	case "visitors":
		cmdVisitors(data, cfg)
	case "vhost":
		cmdVhost(data, cfg)
	case "response-time":
		cmdResponseTime(data, cfg)
	case "asn":
		cmdASN(data, cfg)
	case "ip-profile":
		cmdIPProfile(data, cfg, filterIP)
	case "webshell":
		cmdWebshell(data, cfg)
	case "malformed":
		cmdMalformed(data, cfg)
	case "storm-404":
		cmdStorm404(data, cfg)
	default:
		fmt.Fprintf(os.Stderr, "%sUnknown command: %s%s\n", cRed, command, cReset)
		flag.Usage()
		return 2
	}

	if len(data.ThreatCounts) > 0 {
		return 1
	}
	return 0
}

// ── GeoIP helpers ──

func resolveGeoIP(ips map[string]bool, dbPath string) map[string]string {
	result := make(map[string]string)
	if dbPath == "" {
		return result
	}
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return result
	}
	defer db.Close()

	type geoResult struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}

	for ip := range ips {
		pip := net.ParseIP(ip)
		if pip == nil {
			continue
		}
		var r geoResult
		if err := db.Lookup(pip, &r); err == nil && r.Country.ISOCode != "" {
			result[ip] = r.Country.ISOCode
		} else {
			result[ip] = "??"
		}
	}
	return result
}

func resolveGeoIPFull(ipCounts map[string]int, dbPath string) map[string][2]string {
	result := make(map[string][2]string)
	if dbPath == "" {
		return result
	}
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return result
	}
	defer db.Close()

	type geoResult struct {
		Country struct {
			ISOCode string            `maxminddb:"iso_code"`
			Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
	}

	for ip := range ipCounts {
		pip := net.ParseIP(ip)
		if pip == nil {
			continue
		}
		var r geoResult
		if err := db.Lookup(pip, &r); err == nil && r.Country.ISOCode != "" {
			name := r.Country.Names["en"]
			if name == "" {
				name = "Unknown"
			}
			result[ip] = [2]string{r.Country.ISOCode, name}
		} else {
			result[ip] = [2]string{"??", "Unknown"}
		}
	}
	return result
}

// ── Setup GeoIP ──

func downloadDB(name, url, destPath string) bool {
	if info, err := os.Stat(destPath); err == nil {
		age := int(time.Since(info.ModTime()).Hours() / 24)
		if age < 30 {
			fmt.Printf("  %s%s already present: %s%s\n", cGreen, name, destPath, cReset)
			fmt.Printf("  Updated %d day(s) ago\n", age)
			return true
		}
		fmt.Printf("  %s%s > 30 days, updating...%s\n", cYellow, name, cReset)
	}

	fmt.Printf("  Destination: %s\n", destPath)
	fmt.Printf("  %sDownloading %s...%s\n", cCyan, name, cReset)

	os.MkdirAll(filepath.Dir(destPath), 0755)
	resp, err := http.Get(url)
	if err != nil {
		warn(fmt.Sprintf("Download failed: %v", err))
		return false
	}
	defer resp.Body.Close()

	tmp := destPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		warn(fmt.Sprintf("Error creating file: %v", err))
		return false
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		warn(fmt.Sprintf("Write error: %v", err))
		return false
	}
	f.Close()
	if err := os.Rename(tmp, destPath); err != nil {
		os.Remove(tmp)
		warn(fmt.Sprintf("Rename error: %v", err))
		return false
	}

	info, _ := os.Stat(destPath)
	fmt.Printf("  %sOK%s - %s (%.1fM)\n", cGreen, cReset, destPath, float64(info.Size())/1024/1024)
	return true
}

func cmdSetupGeoIP(cfg Cfg) {
	baseDir := filepath.Join(homeDir, "geoip")
	if os.Getuid() == 0 {
		baseDir = "/usr/share/GeoIP"
	}

	header("GeoIP database setup")
	fmt.Printf("  Source: github.com/P3TERX/GeoLite.mmdb\n\n")

	countryPath := cfgStr(cfg, "geoip_db", "")
	if countryPath == "" {
		countryPath = filepath.Join(baseDir, "GeoLite2-Country.mmdb")
	}
	asnPath := filepath.Join(filepath.Dir(countryPath), "GeoLite2-ASN.mmdb")

	downloadDB("GeoLite2-Country", "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb", countryPath)
	fmt.Println()
	downloadDB("GeoLite2-ASN", "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb", asnPath)
}
