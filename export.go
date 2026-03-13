package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

// ── JSON export ──

type jsonExport struct {
	Version  string          `json:"version"`
	Total    int             `json:"total"`
	Unique   int             `json:"unique_ips"`
	Visitors int             `json:"unique_visitors"`
	Bots     int             `json:"bots"`
	Bytes    int64           `json:"bytes"`
	S4xx     int             `json:"errors_4xx"`
	S5xx     int             `json:"errors_5xx"`
	Threats  int             `json:"threats"`
	TopIPs   []jsonKV        `json:"top_ips"`
	TopURIs  []jsonKV        `json:"top_uris"`
	TopUAs   []jsonKV        `json:"top_uas"`
	Status   []jsonKVInt     `json:"status_codes"`
	Vhosts   []jsonVhost     `json:"vhosts,omitempty"`
	ThreatsByType map[string]int `json:"threats_by_type,omitempty"`
	TopASN   []jsonKV        `json:"top_asn,omitempty"`
}

type jsonKV struct {
	Key   string `json:"key"`
	Value int    `json:"value"`
}

type jsonKVInt struct {
	Code  int `json:"code"`
	Count int `json:"count"`
}

type jsonVhost struct {
	Host string `json:"host"`
	Hits int    `json:"hits"`
	IPs  int    `json:"ips"`
}

func exportJSON(data *ParseData, cfg Cfg, w *os.File) {
	n := cfgInt(cfg, "top_n", 10)
	var totalBytes int64
	for _, b := range data.IPBytes {
		totalBytes += b
	}
	s4xx, s5xx := 0, 0
	for s, c := range data.StatusCounts {
		if s >= 400 && s < 500 {
			s4xx += c
		} else if s >= 500 {
			s5xx += c
		}
	}
	threats := 0
	for _, c := range data.ThreatCounts {
		threats += c
	}

	out := jsonExport{
		Version:  version,
		Total:    data.Total,
		Unique:   len(data.IPCounts),
		Visitors: len(data.UniqueVisitors),
		Bots:     data.BotCount,
		Bytes:    totalBytes,
		S4xx:     s4xx,
		S5xx:     s5xx,
		Threats:  threats,
	}

	for _, kv := range topN(data.IPCounts, n) {
		out.TopIPs = append(out.TopIPs, jsonKV{kv.Key, kv.Val})
	}
	for _, kv := range topN(data.URICounts, n) {
		out.TopURIs = append(out.TopURIs, jsonKV{kv.Key, kv.Val})
	}
	for _, kv := range topN(data.UACounts, n) {
		out.TopUAs = append(out.TopUAs, jsonKV{kv.Key, kv.Val})
	}
	for _, kv := range topNInt(data.StatusCounts, 0) {
		out.Status = append(out.Status, jsonKVInt{kv.Key, kv.Val})
	}
	if len(data.ThreatCounts) > 0 {
		out.ThreatsByType = data.ThreatCounts
	}
	for _, kv := range topN(data.VhostCounts, n) {
		ips := len(data.VhostIPs[kv.Key])
		out.Vhosts = append(out.Vhosts, jsonVhost{kv.Key, kv.Val, ips})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

// ── CSV export ──

func exportCSV(data *ParseData, cfg Cfg, w *os.File) {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Header
	cw.Write([]string{"ip", "hits", "bytes", "unique_uas", "classes", "threats", "first_seen", "last_seen"})

	// Sort IPs by hits desc
	items := topN(data.IPCounts, 0)
	for _, kv := range items {
		ip := kv.Key
		bytes := data.IPBytes[ip]
		uas := len(data.IPUAs[ip])
		classes := ""
		if c := sortedKeys(data.IPClasses[ip]); len(c) > 0 {
			classes = strings.Join(c, ";")
		}
		threats := ""
		if t := sortedKeys(data.IPThreats[ip]); len(t) > 0 {
			threats = strings.Join(t, ";")
		}
		first, last := "", ""
		if t, ok := data.IPFirstSeen[ip]; ok {
			first = t.Format("2006-01-02T15:04:05")
		}
		if t, ok := data.IPLastSeen[ip]; ok {
			last = t.Format("2006-01-02T15:04:05")
		}
		cw.Write([]string{
			ip,
			strconv.Itoa(kv.Val),
			fmt.Sprintf("%d", bytes),
			strconv.Itoa(uas),
			classes,
			threats,
			first,
			last,
		})
	}
}

// ── Export dispatcher ──

func writeExport(path string, format string, data *ParseData, cfg Cfg) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	switch format {
	case "json":
		exportJSON(data, cfg, f)
	case "csv":
		exportCSV(data, cfg, f)
	}
	return nil
}

// Helper for CSV: ensure IP profiling data is populated
func ensureProfileData(data *ParseData) {
	// IPUAs may be empty if not in profiling mode — count from UACounts
	// This is already populated per-IP if profiling was on; otherwise approximate
	if len(data.IPUAs) == 0 {
		// Can't reconstruct per-IP UAs without profiling, just use count
		for ip := range data.IPCounts {
			if data.IPUAs[ip] == nil {
				data.IPUAs[ip] = make(map[string]bool)
			}
		}
	}
}

// ── ASN resolution ──

func resolveASN(ipCounts map[string]int) map[string]string {
	result := make(map[string]string)
	dbPath := findASNDB()
	if dbPath == "" {
		return result
	}
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return result
	}
	defer db.Close()

	type asnResult struct {
		ASN uint   `maxminddb:"autonomous_system_number"`
		Org string `maxminddb:"autonomous_system_organization"`
	}

	for ip := range ipCounts {
		pip := net.ParseIP(ip)
		if pip == nil {
			continue
		}
		var r asnResult
		if err := db.Lookup(pip, &r); err == nil && r.ASN > 0 {
			result[ip] = fmt.Sprintf("AS%d %s", r.ASN, r.Org)
		}
	}
	return result
}

