package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var homeDir string

func init() {
	if u, err := user.Current(); err == nil {
		homeDir = u.HomeDir
	}
}

var defaultCfg = Cfg{
	"top_n":              10,
	"suspect_threshold":  500,
	"ua_threshold":       50,
	"prefix_threshold":   1000,
	"burst_threshold":    30,
	"post_flood_threshold": 200,
	"geoip_db":           "",
	"whitelist":          []string{"5.39.38.0/24", "5.22.211.82"},
	"f2b_whitelist_path": "/etc/fail2ban/jail.d/whitelist-ips.conf",
}

var configPaths = []string{"/etc/an4log/an4log.conf"}
var geoipSearchPaths = []string{
	"/usr/share/GeoIP/GeoLite2-Country.mmdb",
	"/var/lib/GeoIP/GeoLite2-Country.mmdb",
	"/root/geoip/GeoLite2-Country.mmdb",
	"/tmp/geoip/GeoLite2-Country.mmdb",
}

func init() {
	if homeDir != "" {
		configPaths = append(configPaths, filepath.Join(homeDir, ".an4log.conf"))
		geoipSearchPaths = append(geoipSearchPaths, filepath.Join(homeDir, "geoip", "GeoLite2-Country.mmdb"))
	}
}

var intKeys = map[string]bool{
	"top_n": true, "suspect_threshold": true, "ua_threshold": true,
	"prefix_threshold": true, "burst_threshold": true, "post_flood_threshold": true,
}

func loadConfig(path string) Cfg {
	cfg := make(Cfg)
	for k, v := range defaultCfg {
		cfg[k] = v
	}
	paths := configPaths
	if path != "" {
		paths = []string{path}
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.SplitN(sc.Text(), "#", 2)[0]
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if intKeys[key] {
				if n, err := strconv.Atoi(val); err == nil {
					cfg[key] = n
				}
			} else if key == "whitelist" {
				var wl []string
				for _, s := range strings.Split(val, ",") {
					s = strings.TrimSpace(s)
					if s != "" {
						wl = append(wl, s)
					}
				}
				cfg["whitelist"] = wl
			} else if key == "geoip_db" || key == "f2b_whitelist_path" {
				cfg[key] = val
			}
		}
		f.Close()
		break
	}
	return cfg
}

var ipPrefixRE = regexp.MustCompile(`^[0-9]+\.`)

func loadWhitelist(cfg Cfg, extraFile string) ([]string, []net.IPNet) {
	var raw []string
	if wl, ok := cfg["whitelist"].([]string); ok {
		raw = append(raw, wl...)
	}
	// fail2ban
	f2b := cfgStr(cfg, "f2b_whitelist_path", "")
	if f2b != "" {
		if f, err := os.Open(f2b); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.SplitN(sc.Text(), "#", 2)[0]
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "[") {
					continue
				}
				if strings.Contains(line, "=") {
					line = strings.SplitN(line, "=", 2)[1]
				}
				for _, tok := range strings.Fields(line) {
					if ipPrefixRE.MatchString(tok) {
						raw = append(raw, tok)
					}
				}
			}
			f.Close()
		}
	}
	// external file
	if extraFile != "" {
		if f, err := os.Open(extraFile); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.SplitN(sc.Text(), "#", 2)[0]
				line = strings.TrimSpace(line)
				if line != "" && ipPrefixRE.MatchString(line) {
					raw = append(raw, line)
				}
			}
			f.Close()
		}
	}
	var nets []net.IPNet
	for _, entry := range raw {
		cidr := entry
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, *n)
		}
	}
	return raw, nets
}

func findGeoIPDB(cfgPath string) string {
	if cfgPath != "" {
		if _, err := os.Stat(cfgPath); err == nil {
			return cfgPath
		}
	}
	for _, p := range geoipSearchPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func resolveFiles(patterns []string) []string {
	var files []string
	var skipped []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			warn(fmt.Sprintf("Aucun fichier pour: %s", pattern))
			continue
		}
		for _, f := range matches {
			base := filepath.Base(f)
			if strings.Contains(base, ".error.") || strings.HasPrefix(base, "error") {
				skipped = append(skipped, base)
				continue
			}
			info, err := os.Stat(f)
			if err != nil || info.IsDir() {
				warn(fmt.Sprintf("Fichier non lisible: %s", f))
				continue
			}
			files = append(files, f)
		}
	}
	if len(skipped) > 0 {
		warn(fmt.Sprintf("Ignore %d error log(s): %s", len(skipped), strings.Join(skipped, ", ")))
	}
	return files
}

func validateFormat(files []string) bool {
	if len(files) == 0 {
		return true
	}
	f, err := os.Open(files[0])
	if err != nil {
		return true
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	checked, matched := 0, 0
	for sc.Scan() && checked < 10 {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		checked++
		if logRE.MatchString(line) {
			matched++
		}
	}
	if checked > 0 && matched < checked/2 {
		warn(fmt.Sprintf("Format de log non reconnu (%d/%d lignes parsees)", matched, checked))
		warn("Format attendu: Combined Log Format (Apache/Nginx)")
		return false
	}
	return true
}
