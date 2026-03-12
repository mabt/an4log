package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// ── ANSI colors ──

var cBold, cRed, cGreen, cYellow, cCyan, cReset string

func initColors() {
	fi, _ := os.Stdout.Stat()
	if fi != nil && fi.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == "" {
		cBold = "\033[1m"
		cRed = "\033[0;31m"
		cGreen = "\033[0;32m"
		cYellow = "\033[0;33m"
		cCyan = "\033[0;36m"
		cReset = "\033[0m"
	}
}

func disableColors() {
	cBold, cRed, cGreen, cYellow, cCyan, cReset = "", "", "", "", "", ""
}

// ── Output ──

func header(title string) {
	fmt.Printf("\n%s%s=== %s ===%s\n\n", cBold, cGreen, title, cReset)
}

func warn(msg string) {
	fmt.Fprintf(os.Stderr, "%s[!] %s%s\n", cYellow, msg, cReset)
}

// ── Formatting ──

func fmtSize(n int64) string {
	f := float64(n)
	for _, u := range []string{"o", "K", "M", "G", "T"} {
		if f < 1024 || u == "T" {
			if u == "o" {
				return fmt.Sprintf("%d%s", int(f), u)
			}
			return fmt.Sprintf("%.1f%s", f, u)
		}
		f /= 1024
	}
	return fmt.Sprintf("%.1fP", f)
}

func fmtBar(val, maxVal, width int) string {
	if maxVal <= 0 {
		return ""
	}
	filled := val * width / maxVal
	if filled > width {
		filled = width
	}
	return cCyan + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + cReset
}

func fmtPct(val, total int) string {
	if total <= 0 {
		return ""
	}
	return fmt.Sprintf("%5.1f%%", float64(val)/float64(total)*100)
}

func fmtKey(key string, maxLen int) string {
	runes := []rune(key)
	if len(runes) > maxLen {
		return string(runes[:maxLen-1]) + "…"
	}
	return key
}

func fmtComma(n int) string {
	if n < 0 {
		return fmt.Sprintf("%d", n)
	}
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	rem := len(s) % 3
	if rem == 0 {
		rem = 3
	}
	b.WriteString(s[:rem])
	for i := rem; i < len(s); i += 3 {
		b.WriteByte(',')
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// ── Sorting ──

func topN(m map[string]int, n int) []KV {
	items := make([]KV, 0, len(m))
	for k, v := range m {
		items = append(items, KV{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Val != items[j].Val {
			return items[i].Val > items[j].Val
		}
		return items[i].Key < items[j].Key
	})
	if n > 0 && len(items) > n {
		items = items[:n]
	}
	return items
}

func topNInt(m map[int]int, n int) []KVInt {
	items := make([]KVInt, 0, len(m))
	for k, v := range m {
		items = append(items, KVInt{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Val > items[j].Val })
	if n > 0 && len(items) > n {
		items = items[:n]
	}
	return items
}

func topN64(m map[string]int64, n int) []KV64 {
	items := make([]KV64, 0, len(m))
	for k, v := range m {
		items = append(items, KV64{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Val > items[j].Val })
	if n > 0 && len(items) > n {
		items = items[:n]
	}
	return items
}

func showTop(counter map[string]int, n, total, truncate int) {
	items := topN(counter, n)
	if len(items) == 0 {
		return
	}
	maxVal := items[0].Val
	for _, kv := range items {
		pct, bar := "", ""
		if total > 0 {
			pct = "  " + fmtPct(kv.Val, total)
			bar = "  " + fmtBar(kv.Val, maxVal, 20)
		}
		display := kv.Key
		if truncate > 0 {
			display = fmtKey(kv.Key, truncate)
		}
		fmt.Printf("  %10s%s%s  %s\n", fmtComma(kv.Val), pct, bar, display)
	}
}

// ── Config helpers ──

func cfgInt(cfg Cfg, key string, def int) int {
	if v, ok := cfg[key]; ok {
		if i, ok := v.(int); ok {
			return i
		}
	}
	return def
}

func cfgStr(cfg Cfg, key string, def string) string {
	if v, ok := cfg[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

// ── IP/Network ──

func isWhitelisted(ipStr string, nets []net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrefixWhitelisted(prefix string, rawWL []string) bool {
	for _, e := range rawWL {
		if strings.HasPrefix(e, prefix+".") {
			return true
		}
	}
	return false
}

func isProtectedIP(ip string, data *ParseData) bool {
	c := data.IPClasses[ip]
	return c != nil && (c["PAYMENT"] || c["MONITORING"])
}

func ipScore(ip string, data *ParseData, cfg Cfg) int {
	score := 0
	for t := range data.IPThreats[ip] {
		s := threatScores[t]
		if s == 0 {
			s = 1
		}
		cnt := 1
		if m, ok := data.ThreatIPs[t]; ok {
			if c := m[ip]; c > 0 {
				cnt = c
			}
		}
		score += s * cnt
	}
	thresh := cfgInt(cfg, "suspect_threshold", 500)
	if c := data.IPCounts[ip]; c > thresh {
		score += (c - thresh) / 100 * 3
	}
	if eu := data.EmptyUAIPs[ip]; eu > cfgInt(cfg, "ua_threshold", 50) {
		score += eu
	}
	return score
}

// ── Set helpers ──

func ensureStringSet(m map[string]map[string]bool, key string) map[string]bool {
	if m[key] == nil {
		m[key] = make(map[string]bool)
	}
	return m[key]
}

func ensureIntMap(m map[string]map[string]int, key string) map[string]int {
	if m[key] == nil {
		m[key] = make(map[string]int)
	}
	return m[key]
}

func ensureStatusMap(m map[string]map[int]int, key string) map[int]int {
	if m[key] == nil {
		m[key] = make(map[int]int)
	}
	return m[key]
}
