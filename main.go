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
	var excludeBots, outputIPs, showVersion bool
	var suspectThreshold, uaThreshold, burstThreshold int

	flag.Var(&files, "d", "Fichier(s) log (glob ok, repeatable)")
	flag.IntVar(&topN, "n", 0, "Nombre de resultats (defaut: 10)")
	flag.StringVar(&geoipDB, "g", "", "Chemin base GeoLite2-Country.mmdb")
	flag.StringVar(&whitelistFile, "w", "", "Fichier whitelist externe")
	flag.StringVar(&configFile, "c", "", "Fichier de configuration")
	flag.StringVar(&since, "since", "", "Filtrer depuis: 30m, 2h, 1d, 2026-03-09")
	flag.StringVar(&filterIP, "ip", "", "Filtrer / profiler une IP")
	flag.BoolVar(&excludeBots, "exclude-bots", false, "Exclure les bots connus")
	flag.BoolVar(&outputIPs, "output-ips", false, "Sortie IPs brutes (pour pipe)")
	flag.StringVar(&groupBy, "group-by", "", "Grouper par day ou month")
	flag.StringVar(&htmlFile, "html", "", "Generer un rapport HTML")
	flag.IntVar(&suspectThreshold, "suspect-threshold", 0, "Seuil IPs suspectes")
	flag.IntVar(&uaThreshold, "ua-threshold", 0, "Seuil IPs sans UA")
	flag.IntVar(&burstThreshold, "burst-threshold", 0, "Seuil burst req/min")
	flag.BoolVar(&showVersion, "v", false, "Afficher la version")
	flag.BoolVar(&showVersion, "version", false, "Afficher la version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "an4log v%s - Analyseur de logs Apache/Nginx\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: an4log -d FILE [options] [COMMANDE]\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Commandes:
  all, summary, classify, ip, ua, uri, prefix, status, heavy, methods,
  timeline, hour, minute, slow, 404, 403, crawlers, suspect, empty-ua,
  burst, threat, actions, sql, xss, traversal, scanners, wp-attack,
  post-flood, countries, setup-geoip

Exemples:
  an4log -d /var/log/apache2/access.log
  an4log -d access.log -n 20 status
  an4log -d access.log -since 1h threat
  an4log -d access.log -ip 1.2.3.4
  an4log -d access.log actions -output-ips
  an4log -d access.log -html rapport.html
  an4log -d access*.log -group-by day
`)
	}

	flag.Parse()

	if showVersion {
		fmt.Printf("an4log v%s\n", version)
		return 0
	}

	// Parse remaining args for command and extra files
	command := "all"
	validCmds := map[string]bool{
		"all": true, "summary": true, "classify": true, "ip": true, "ua": true,
		"uri": true, "prefix": true, "status": true, "heavy": true, "methods": true,
		"timeline": true, "hour": true, "minute": true, "slow": true, "404": true,
		"403": true, "crawlers": true, "suspect": true, "empty-ua": true, "burst": true,
		"threat": true, "actions": true, "sql": true, "xss": true, "traversal": true,
		"scanners": true, "wp-attack": true, "post-flood": true, "countries": true,
		"setup-geoip": true, "ip-profile": true,
	}
	remaining := flag.Args()
	var extraFiles []string
	for _, arg := range remaining {
		if validCmds[arg] {
			command = arg
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
		fmt.Fprintf(os.Stderr, "Erreur: fichier log requis (-d <fichier>)\n")
		flag.Usage()
		return 2
	}

	// Resolve files
	resolved := resolveFiles(files)
	if len(resolved) == 0 {
		fmt.Fprintf(os.Stderr, "%sErreur: aucun fichier log trouve%s\n", cRed, cReset)
		return 2
	}

	// Validate format
	if !validateFormat(resolved) {
		return 2
	}

	// Header
	if !outputIPs {
		fmt.Printf("%san4log v%s%s\n", cBold, version, cReset)
		if len(resolved) == 1 {
			fmt.Printf("Fichier: %s%s%s\n", cCyan, resolved[0], cReset)
		} else {
			fmt.Printf("Fichiers: %s%d%s fichiers\n", cBold, len(resolved), cReset)
			limit := 5
			if len(resolved) < limit {
				limit = len(resolved)
			}
			for _, f := range resolved[:limit] {
				fmt.Printf("  %s%s%s\n", cCyan, f, cReset)
			}
			if len(resolved) > 5 {
				fmt.Printf("  ... +%d autres\n", len(resolved)-5)
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
		for _, f := range resolved {
			if info, err := os.Stat(f); err == nil {
				sizeBytes += info.Size()
			}
		}
		fmt.Printf("Lignes: %s%s%s | Taille: %s%s%s | Parse: %s%.2fs%s\n",
			cBold, fmtComma(data.Total), cReset,
			cBold, fmtSize(sizeBytes), cReset,
			cBold, elapsed, cReset)
		if data.ParseErrors > 0 {
			warn(fmt.Sprintf("%d ligne(s) non parsee(s)", data.ParseErrors))
		}
		if since != "" {
			fmt.Printf("Filtre: %s--since %s%s\n", cYellow, since, cReset)
		}
		if filterIP != "" {
			fmt.Printf("Filtre IP: %s%s%s\n", cYellow, filterIP, cReset)
		}
		if excludeBots {
			fmt.Printf("Filtre: %s--exclude-bots%s\n", cYellow, cReset)
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
			warn(fmt.Sprintf("Erreur ecriture HTML: %v", err))
		} else {
			fmt.Printf("%sRapport HTML genere: %s%s\n", cGreen, htmlFile, cReset)
		}
		if !outputIPs && command == "all" {
			if len(data.ThreatCounts) > 0 {
				return 1
			}
			return 0
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
	case "ip-profile":
		cmdIPProfile(data, cfg, filterIP)
	default:
		fmt.Fprintf(os.Stderr, "%sCommande inconnue: %s%s\n", cRed, command, cReset)
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
				name = "Inconnu"
			}
			result[ip] = [2]string{r.Country.ISOCode, name}
		} else {
			result[ip] = [2]string{"??", "Inconnu"}
		}
	}
	return result
}

// ── Setup GeoIP ──

func cmdSetupGeoIP(cfg Cfg) {
	defaultPath := filepath.Join(homeDir, "geoip", "GeoLite2-Country.mmdb")
	if os.Getuid() == 0 {
		defaultPath = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
	}
	dbPath := cfgStr(cfg, "geoip_db", "")
	if dbPath == "" {
		dbPath = defaultPath
	}
	url := "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

	header("Installation GeoLite2-Country.mmdb")

	if info, err := os.Stat(dbPath); err == nil {
		age := int(time.Since(info.ModTime()).Hours() / 24)
		if age < 30 {
			fmt.Printf("  %sBase deja presente: %s%s\n", cGreen, dbPath, cReset)
			fmt.Printf("  Mise a jour il y a %d jour(s)\n", age)
			fmt.Printf("\n  Pour forcer: rm %s && an4log setup-geoip\n", dbPath)
			return
		}
		fmt.Printf("  %sBase > 30 jours, mise a jour...%s\n", cYellow, cReset)
	}

	fmt.Printf("  Destination: %s\n", dbPath)
	fmt.Printf("  Source: github.com/P3TERX/GeoLite.mmdb\n\n")

	os.MkdirAll(filepath.Dir(dbPath), 0755)

	fmt.Printf("  %sTelechargement en cours...%s\n", cCyan, cReset)
	resp, err := http.Get(url)
	if err != nil {
		warn(fmt.Sprintf("Echec du telechargement: %v", err))
		return
	}
	defer resp.Body.Close()

	tmp := dbPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		warn(fmt.Sprintf("Erreur creation fichier: %v", err))
		return
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		warn(fmt.Sprintf("Erreur ecriture: %v", err))
		return
	}
	f.Close()
	if err := os.Rename(tmp, dbPath); err != nil {
		os.Remove(tmp)
		warn(fmt.Sprintf("Erreur rename: %v", err))
		return
	}

	info, _ := os.Stat(dbPath)
	fmt.Printf("\n  %sOK%s - %s (%.1fM)\n", cGreen, cReset, dbPath, float64(info.Size())/1024/1024)
}
