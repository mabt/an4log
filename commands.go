package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

func cmdIP(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d IPs", n))
	showTop(data.IPCounts, n, data.Total, 42)
}

func cmdUA(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d User-Agents", n))
	showTop(data.UACounts, n, data.Total, 0)
}

func cmdURI(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d URIs", n))
	showTop(data.URICounts, n, data.Total, 0)
}

func cmdPrefix(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d prefixes IP (xxx.xxx.*)", n))
	showTop(data.PrefixCounts, n, data.Total, 0)
}

func cmdStatus(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d HTTP codes", n))
	items := topNInt(data.StatusCounts, n)
	if len(items) == 0 {
		return
	}
	maxVal := items[0].Val
	for _, kv := range items {
		pct := fmtPct(kv.Val, data.Total)
		bar := fmtBar(kv.Val, maxVal, 20)
		fmt.Printf("  %10s  %s  %s  %d\n", fmtComma(kv.Val), pct, bar, kv.Key)
	}
}

func cmdHeavy(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d IPs by volume", n))
	items := topN64(data.IPBytes, n)
	if len(items) == 0 {
		return
	}
	var totalBytes int64
	for _, v := range data.IPBytes {
		totalBytes += v
	}
	maxVal := items[0].Val
	for _, kv := range items {
		pct := fmtPct(int(kv.Val), int(totalBytes))
		bar := fmtBar(int(kv.Val), int(maxVal), 20)
		fmt.Printf("  %8s  %s  %s  %s\n", fmtSize(kv.Val), pct, bar, kv.Key)
	}
}

func cmdMethods(data *ParseData, cfg Cfg) {
	header("HTTP methods")
	showTop(data.MethodCounts, cfgInt(cfg, "top_n", 10), data.Total, 0)
}

func cmdHour(data *ParseData, cfg Cfg) {
	header("Requests per hour")
	if len(data.HourCounts) == 0 {
		return
	}
	maxVal := 0
	for _, c := range data.HourCounts {
		if c > maxVal {
			maxVal = c
		}
	}
	for h := 0; h < 24; h++ {
		hk := fmt.Sprintf("%02d", h)
		count := data.HourCounts[hk]
		pct := fmtPct(count, data.Total)
		bar := fmtBar(count, maxVal, 20)
		fmt.Printf("  %sh  %8s  %s  %s\n", hk, fmtComma(count), pct, bar)
	}
}

func cmdMinute(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d peaks per minute", n))
	showTop(data.MinuteCounts, n, 0, 0)
}

func cmdSlow(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d slowest requests", n))
	for i, sr := range data.SlowReqs {
		if i >= n {
			break
		}
		fmt.Printf("  %10s  %s\n", fmtComma(sr.Time), sr.URI)
	}
}

func cmd404(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d 404 URIs", n))
	total := 0
	for _, c := range data.URI404 {
		total += c
	}
	showTop(data.URI404, n, total, 0)
}

func cmd403(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d blocked IPs (403)", n))
	total := 0
	for _, c := range data.IP403 {
		total += c
	}
	showTop(data.IP403, n, total, 42)
}

func cmdCrawlers(data *ParseData, cfg Cfg) {
	header("Detected bots/crawlers")
	showTop(data.BotUAs, cfgInt(cfg, "top_n", 10), data.BotCount, 0)
}

func cmdSuspect(data *ParseData, cfg Cfg) {
	thresh := cfgInt(cfg, "suspect_threshold", 500)
	header(fmt.Sprintf("Suspect IPs (> %d requests)", thresh))
	found := make(map[string]int)
	for ip, c := range data.IPCounts {
		if c > thresh {
			found[ip] = c
		}
	}
	showTop(found, cfgInt(cfg, "top_n", 10), data.Total, 42)
}

func cmdEmptyUA(data *ParseData, cfg Cfg) {
	header("Requests without User-Agent")
	total := 0
	for _, c := range data.EmptyUAIPs {
		total += c
	}
	showTop(data.EmptyUAIPs, cfgInt(cfg, "top_n", 10), total, 42)
}

func cmdSQL(data *ParseData, cfg Cfg) {
	header("SQL injection attempts")
	m := data.ThreatIPs["SQL"]
	if m == nil {
		m = make(map[string]int)
	}
	showTop(m, cfgInt(cfg, "top_n", 10), 0, 0)
}

func cmdXSS(data *ParseData, cfg Cfg) {
	header("XSS attempts")
	m := data.ThreatIPs["XSS"]
	if m == nil {
		m = make(map[string]int)
	}
	showTop(m, cfgInt(cfg, "top_n", 10), 0, 0)
}

func cmdTraversal(data *ParseData, cfg Cfg) {
	header("Path traversal attempts")
	m := data.ThreatIPs["TRAVERSAL"]
	if m == nil {
		m = make(map[string]int)
	}
	showTop(m, cfgInt(cfg, "top_n", 10), 0, 0)
}

func cmdScanners(data *ParseData, cfg Cfg) {
	header("Scanner detection")
	showTop(data.ScannerUAs, cfgInt(cfg, "top_n", 10), 0, 0)
}

func cmdWPAttack(data *ParseData, cfg Cfg) {
	header("WordPress attacks")
	m := data.ThreatIPs["WP"]
	if m == nil {
		m = make(map[string]int)
	}
	showTop(m, cfgInt(cfg, "top_n", 10), 0, 0)
}

func cmdPostFlood(data *ParseData, cfg Cfg) {
	thresh := cfgInt(cfg, "post_flood_threshold", 200)
	header(fmt.Sprintf("POST flood per IP (> %d)", thresh))
	found := make(map[string]int)
	for ip, c := range data.PostIPs {
		if c > thresh && !isProtectedIP(ip, data) {
			found[ip] = c
		}
	}
	showTop(found, cfgInt(cfg, "top_n", 10), 0, 42)
}

func cmdBurst(data *ParseData, cfg Cfg) {
	thresh := cfgInt(cfg, "burst_threshold", 30)
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Burst IPs (> %d req/min)", thresh))
	type burst struct {
		count int
		ip    string
		mkey  string
	}
	var bursts []burst
	for ip, minutes := range data.IPBurst {
		for mkey, count := range minutes {
			if count > thresh {
				bursts = append(bursts, burst{count, ip, mkey})
			}
		}
	}
	sort.Slice(bursts, func(i, j int) bool { return bursts[i].count > bursts[j].count })
	for i, b := range bursts {
		if i >= n {
			break
		}
		fmt.Printf("  %6s  %-16s  %s\n", fmtComma(b.count), b.ip, b.mkey)
	}
}

func cmdSummary(data *ParseData, cfg Cfg) {
	header("Quick summary")
	total := data.Total
	unique := len(data.IPCounts)
	bots := data.BotCount
	var euTotal int
	for _, c := range data.EmptyUAIPs {
		euTotal += c
	}
	var totalBytes int64
	for _, v := range data.IPBytes {
		totalBytes += v
	}
	s4xx, s5xx := 0, 0
	for s, c := range data.StatusCounts {
		if s >= 400 && s < 500 {
			s4xx += c
		} else if s >= 500 && s < 600 {
			s5xx += c
		}
	}
	botPct, err4Pct, err5Pct := 0, 0, 0
	if total > 0 {
		botPct = bots * 100 / total
		err4Pct = s4xx * 100 / total
		err5Pct = s5xx * 100 / total
	}

	fmt.Printf("  Total requests    : %s%s%s\n", cBold, fmtComma(total), cReset)
	fmt.Printf("  Unique IPs        : %s%s%s\n", cBold, fmtComma(unique), cReset)
	fmt.Printf("  Total volume      : %s%s%s\n", cBold, fmtSize(totalBytes), cReset)
	fmt.Printf("  Bots/Crawlers     : %s%s%s (%d%%)\n", cBold, fmtComma(bots), cReset, botPct)
	fmt.Printf("  No User-Agent     : %s%s%s\n", cBold, fmtComma(euTotal), cReset)
	fmt.Printf("  4xx errors        : %s%s%s (%d%%)\n", cBold, fmtComma(s4xx), cReset, err4Pct)
	fmt.Printf("  5xx errors        : %s%s%s (%d%%)\n", cBold, fmtComma(s5xx), cReset, err5Pct)

	suspect := 0
	thresh := cfgInt(cfg, "suspect_threshold", 500)
	for _, c := range data.IPCounts {
		if c > thresh {
			suspect++
		}
	}
	threats := 0
	for _, c := range data.ThreatCounts {
		threats += c
	}
	fmt.Println()
	if suspect > 0 {
		fmt.Printf("  %s!! %d suspect IP(s) (> %d req)%s\n", cRed, suspect, thresh, cReset)
	}
	if threats > 0 {
		fmt.Printf("  %s!! %s malicious request(s) detected%s\n", cRed, fmtComma(threats), cReset)
	}
	if err5Pct > 5 {
		fmt.Printf("  %s!! High 5xx error rate (%d%%)%s\n", cRed, err5Pct, cReset)
	}
	if len(data.WebshellIPs) > 0 {
		fmt.Printf("  %s!! %d IP(s) scanning webshells%s\n", cRed, len(data.WebshellIPs), cReset)
	}
	malformedTotal := 0
	for _, c := range data.MalformedURLs {
		malformedTotal += c
	}
	if malformedTotal > 0 {
		fmt.Printf("  %s!! %s malformed URLs (domain in path)%s\n", cRed, fmtComma(malformedTotal), cReset)
	}
	storm404Count := 0
	burstThresh404 := cfgInt(cfg, "burst_threshold", 30)
	for _, c := range data.Storm404Minutes {
		if c > burstThresh404 {
			storm404Count++
		}
	}
	if storm404Count > 0 {
		fmt.Printf("  %s!! %d 404 storm(s) detected (> %d 404/min)%s\n", cRed, storm404Count, burstThresh404, cReset)
	}
	facetTotal := 0
	for _, c := range data.FacetURIs {
		if c >= 100 {
			facetTotal += c
		}
	}
	facetPct := 0
	if total > 0 {
		facetPct = facetTotal * 100 / total
	}
	if facetPct > 10 {
		fmt.Printf("  %s!! %s faceted/filtered requests (%d%% of traffic)%s\n", cYellow, fmtComma(facetTotal), facetPct, cReset)
	}
	if suspect == 0 && threats == 0 && err5Pct <= 5 && len(data.WebshellIPs) == 0 && malformedTotal == 0 && storm404Count == 0 && facetPct <= 10 {
		fmt.Printf("  %sNo alerts%s\n", cGreen, cReset)
	}

	fmt.Printf("\n  %sTop 3 IPs:%s\n", cBold, cReset)
	for _, kv := range topN(data.IPCounts, 3) {
		fmt.Printf("    %8s  %s\n", fmtComma(kv.Val), kv.Key)
	}
	fmt.Printf("\n  %sTop 3 User-Agents:%s\n", cBold, cReset)
	for _, kv := range topN(data.UACounts, 3) {
		fmt.Printf("    %8s  %s\n", fmtComma(kv.Val), kv.Key)
	}
}

func cmdThreat(data *ParseData, cfg Cfg) {
	header("Combined threat view")
	labels := []struct{ key, label string }{
		{"SQL", "SQL Injection"}, {"XSS", "XSS"}, {"TRAVERSAL", "Path Traversal"},
		{"SCAN", "Scanners"}, {"WEBSHELL", "Webshell scans"}, {"WP", "WordPress"}, {"SENSITIVE", "Sensitive files"},
	}
	hasThreat := false
	for _, l := range labels {
		count := data.ThreatCounts[l.key]
		if count <= 0 {
			continue
		}
		hasThreat = true
		fmt.Printf("  %s%-18s%s %s hits\n", cRed, l.label, cReset, fmtComma(count))
		if l.key == "SCAN" {
			for _, kv := range topN(data.ScannerUAs, 5) {
				fmt.Printf("    %6s  %s\n", fmtComma(kv.Val), kv.Key)
			}
		} else if m := data.ThreatIPs[l.key]; m != nil {
			for _, kv := range topN(m, 5) {
				fmt.Printf("    %6s  %s\n", fmtComma(kv.Val), kv.Key)
			}
		}
		fmt.Println()
	}

	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d malicious IPs (by score)", n))
	type scored struct {
		score int
		ip    string
	}
	var items []scored
	for ip := range data.IPThreats {
		items = append(items, scored{ipScore(ip, data, cfg), ip})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].score > items[j].score })
	for i, s := range items {
		if i >= n {
			break
		}
		types := sortedKeys(data.IPThreats[s.ip])
		hits := data.IPCounts[s.ip]
		fmt.Printf("  %sscore=%4d%s  %-16s  %s hits  [%s]\n",
			cRed, s.score, cReset, s.ip, fmtComma(hits), strings.Join(types, ","))
	}
	if !hasThreat {
		fmt.Printf("  %sNo threats detected%s\n", cGreen, cReset)
	}
}

func cmdClassify(data *ParseData, cfg Cfg) {
	header("Traffic classification")
	total := data.Total
	if total == 0 {
		fmt.Printf("  %sNo requests%s\n", cYellow, cReset)
		return
	}
	cats := []struct{ key, label string }{
		{"HUMAN", "Human (browsers)"}, {"PAYMENT", "Payment (Lyra, PayPal, Stripe...)"},
		{"MONITORING", "Monitoring (Uptime, Sansec...)"}, {"LEGIT_BOT", "Legitimate bots (Google, Bing...)"},
		{"SEO", "SEO (Semrush, Ahrefs, OnCrawl...)"}, {"AI_BOT", "AI (GPTBot, ClaudeBot...)"},
		{"UNKNOWN", "No User-Agent / unknown"},
	}
	colors := map[string]string{
		"HUMAN": cGreen, "PAYMENT": cCyan, "MONITORING": cCyan,
		"LEGIT_BOT": cGreen, "SEO": cYellow, "AI_BOT": cYellow, "UNKNOWN": cRed,
	}
	maxVal := 1
	for _, c := range data.UAClassCounts {
		if c > maxVal {
			maxVal = c
		}
	}
	for _, cat := range cats {
		count := data.UAClassCounts[cat.key]
		if count == 0 && cat.key == "UNKNOWN" {
			continue
		}
		ips := len(data.UAClassIPs[cat.key])
		pct := float64(count) / float64(total) * 100
		col := colors[cat.key]
		bar := fmtBar(count, maxVal, 15)
		ipStr := ""
		if ips > 0 {
			ipStr = fmt.Sprintf("  (%d IPs)", ips)
		}
		fmt.Printf("  %s%-40s%s  %8s  %5.1f%%  %s%s\n",
			col, cat.label, cReset, fmtComma(count), pct, bar, ipStr)
	}

	// Payment URIs
	if len(data.PaymentHits) > 0 {
		n := cfgInt(cfg, "top_n", 10)
		header("Payment activity (checkout/payment/webhook URIs)")
		for _, kv := range topN(data.PaymentHits, n) {
			classes := "HUMAN"
			if c := sortedKeys(data.IPClasses[kv.Key]); len(c) > 0 {
				classes = strings.Join(c, ",")
			}
			prot := ""
			if isProtectedIP(kv.Key, data) {
				prot = fmt.Sprintf("  %s[PROTECTED]%s", cGreen, cReset)
			}
			fmt.Printf("  %6s  %-16s  [%s]%s\n", fmtComma(kv.Val), kv.Key, classes, prot)
		}
	}

	// Protected IPs
	protected := make(map[string]bool)
	for _, cls := range []string{"PAYMENT", "MONITORING"} {
		for ip := range data.UAClassIPs[cls] {
			protected[ip] = true
		}
	}
	if len(protected) > 0 {
		header("Protected IPs (payment + monitoring)")
		fmt.Printf("  %sThese IPs will never be proposed for banning in 'actions'%s\n\n", cCyan, cReset)
		var ips []string
		for ip := range protected {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		for _, ip := range ips {
			classes := strings.Join(sortedKeys(data.IPClasses[ip]), ",")
			hits := data.IPCounts[ip]
			fmt.Printf("  %8s  %-16s  [%s]\n", fmtComma(hits), ip, classes)
		}
	}
}

func cmdCountries(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d countries (GeoIP)", n))
	dbPath := findGeoIPDB(cfgStr(cfg, "geoip_db", ""))
	if dbPath == "" {
		warn("GeoIP database not found")
		fmt.Println("    an4log setup-geoip")
		return
	}
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		warn(fmt.Sprintf("Error opening GeoIP: %v", err))
		return
	}
	defer db.Close()

	type geoResult struct {
		Country struct {
			ISOCode string            `maxminddb:"iso_code"`
			Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
	}

	countryIPs := make(map[string]int)
	countryHits := make(map[string]int)
	for ip, hits := range data.IPCounts {
		pip := net.ParseIP(ip)
		var result geoResult
		key := "??|Unknown"
		if pip != nil {
			if err := db.Lookup(pip, &result); err == nil && result.Country.ISOCode != "" {
				name := result.Country.Names["en"]
				if name == "" {
					name = "Unknown"
				}
				key = result.Country.ISOCode + "|" + name
			}
		}
		countryIPs[key]++
		countryHits[key] += hits
	}

	totalIPs := len(data.IPCounts)
	totalHits := data.Total
	fmt.Printf("  Total: %d unique IPs, %d hits\n\n", totalIPs, totalHits)
	fmt.Printf("%3s  %-30s %4s  | %12s | %12s | %7s\n", "#", "Country", "Code", "Unique IPs", "Hits", "% hits")
	fmt.Println(strings.Repeat("-", 85))
	for i, kv := range topN(countryHits, n) {
		parts := strings.SplitN(kv.Key, "|", 2)
		iso, name := parts[0], parts[1]
		ips := countryIPs[kv.Key]
		pct := float64(kv.Val) / float64(totalHits) * 100
		fmt.Printf("%3d  %-30s %4s  | %12s | %12s | %6.2f%%\n",
			i+1, name, iso, fmtComma(ips), fmtComma(kv.Val), pct)
	}
}

func cmdTimeline(data *ParseData, cfg Cfg) {
	ds := data.DayStats
	gb := data.GroupBy
	if len(ds) == 0 {
		fmt.Printf("  %sNo time data%s\n", cYellow, cReset)
		return
	}
	if gb == "" {
		fmt.Printf("  %sUse --group-by day|month%s\n", cYellow, cReset)

		return
	}

	type statEntry struct {
		key   string
		total int
		ips   int
		threats int
		s4xx  int
		s5xx  int
		bytes int64
		bots  int
	}

	var entries []statEntry
	if gb == "month" {
		months := aggregateMonths(data.DayStats)
		for k, ms := range months {
			entries = append(entries, statEntry{k, ms.Total, len(ms.IPs), ms.Threats, ms.S4xx, ms.S5xx, ms.Bytes, ms.Bots})
		}
		sort.Slice(entries, func(i, j int) bool { return monthSortKey(entries[i].key).Before(monthSortKey(entries[j].key)) })
		header(fmt.Sprintf("Traffic by month (%d months)", len(entries)))
	} else {
		for k, d := range ds {
			entries = append(entries, statEntry{k, d.Total, len(d.IPs), d.Threats, d.S4xx, d.S5xx, d.Bytes, d.Bots})
		}
		sort.Slice(entries, func(i, j int) bool { return daySortKey(entries[i].key).Before(daySortKey(entries[j].key)) })
		header(fmt.Sprintf("Traffic by day (%d day(s))", len(entries)))
	}

	maxTotal := 0
	for _, e := range entries {
		if e.total > maxTotal {
			maxTotal = e.total
		}
	}

	fmt.Printf("  %12s  %10s  %6s  %8s  %6s  %5s  %8s  %6s\n",
		"Period", "Requests", "IPs", "Threats", "4xx", "5xx", "Volume", "Bots")
	fmt.Printf("  %s  %s  %s  %s  %s  %s  %s  %s\n",
		strings.Repeat("-", 12), strings.Repeat("-", 10), strings.Repeat("-", 6),
		strings.Repeat("-", 8), strings.Repeat("-", 6), strings.Repeat("-", 5),
		strings.Repeat("-", 8), strings.Repeat("-", 6))

	for _, e := range entries {
		bar := fmtBar(e.total, maxTotal, 12)
		threatStr := fmt.Sprintf("%8s", fmtComma(e.threats))
		if e.threats > 0 {
			threatStr = fmt.Sprintf("%s%8s%s", cRed, fmtComma(e.threats), cReset)
		}
		s5Str := fmt.Sprintf("%5s", fmtComma(e.s5xx))
		if e.s5xx > 0 {
			s5Str = fmt.Sprintf("%s%5s%s", cRed, fmtComma(e.s5xx), cReset)
		}
		fmt.Printf("  %12s  %10s  %6s  %s  %6s  %s  %8s  %6s  %s\n",
			e.key, fmtComma(e.total), fmtComma(e.ips), threatStr,
			fmtComma(e.s4xx), s5Str, fmtSize(e.bytes), fmtComma(e.bots), bar)
	}
}

func cmdIPProfile(data *ParseData, cfg Cfg, filterIP string) {
	header(fmt.Sprintf("IP profile: %s", filterIP))
	total := data.Total
	fmt.Printf("  Total requests: %s%s%s\n", cBold, fmtComma(total), cReset)
	if total == 0 {
		fmt.Printf("  %sNo requests found for this IP%s\n", cYellow, cReset)
		return
	}
	if fs, ok := data.IPFirstSeen[filterIP]; ok {
		fmt.Printf("  First request    : [%s]\n", fs.Format("02/Jan/2006:15:04:05"))
	}
	if ls, ok := data.IPLastSeen[filterIP]; ok {
		fmt.Printf("  Last request     : [%s]\n", ls.Format("02/Jan/2006:15:04:05"))
	}
	n := cfgInt(cfg, "top_n", 10)
	fmt.Printf("\n  %sUser-Agents:%s\n", cBold, cReset)
	if uas := data.IPUAs[filterIP]; uas != nil {
		sorted := sortedKeys(uas)
		for _, ua := range sorted {
			fmt.Printf("    %s\n", ua)
		}
	}
	fmt.Printf("\n  %sHTTP codes:%s\n", cBold, cReset)
	if st := data.IPStatuses[filterIP]; st != nil {
		for _, kv := range topNInt(st, 0) {
			fmt.Printf("    %-6d %d\n", kv.Val, kv.Key)
		}
	}
	fmt.Printf("\n  %sTop %d URIs:%s\n", cBold, n, cReset)
	if uris := data.IPURIs[filterIP]; uris != nil {
		for _, kv := range topN(uris, n) {
			fmt.Printf("    %-6d %s\n", kv.Val, kv.Key)
		}
	}
	fmt.Printf("\n  %sMethods:%s\n", cBold, cReset)
	if methods := data.IPMethods[filterIP]; methods != nil {
		for _, kv := range topN(methods, 0) {
			fmt.Printf("    %-6d %s\n", kv.Val, kv.Key)
		}
	}
	fmt.Printf("\n  %sRequests per hour:%s\n", cBold, cReset)
	if hours := data.IPHours[filterIP]; hours != nil {
		for _, kv := range topN(hours, n) {
			fmt.Printf("    %-6d %sh\n", kv.Val, kv.Key)
		}
	}
	if threats := data.IPThreats[filterIP]; len(threats) > 0 {
		types := sortedKeys(threats)
		fmt.Printf("\n  %sThreats detected: %s%s\n", cRed, strings.Join(types, ", "), cReset)
		fmt.Printf("  Score: %d\n", ipScore(filterIP, data, cfg))
	}
}

func cmdActions(data *ParseData, cfg Cfg, geo map[string]string, wlRaw []string, wlNets []net.IPNet, outputIPs bool) {
	if geo == nil {
		geo = make(map[string]string)
	}

	// Categorize
	type scoredIP struct {
		ip    string
		score int
	}
	var attackIPs []scoredIP
	for ip := range data.IPThreats {
		s := ipScore(ip, data, cfg)
		if s >= 10 {
			attackIPs = append(attackIPs, scoredIP{ip, s})
		}
	}
	sort.Slice(attackIPs, func(i, j int) bool { return attackIPs[i].score > attackIPs[j].score })

	thresh := cfgInt(cfg, "suspect_threshold", 500)
	var suspectIPs []string
	for _, kv := range topN(data.IPCounts, 0) {
		if kv.Val > thresh && data.IPThreats[kv.Key] == nil {
			suspectIPs = append(suspectIPs, kv.Key)
		}
	}

	uaThresh := cfgInt(cfg, "ua_threshold", 50)
	var emptyUAList []string
	for _, kv := range topN(data.EmptyUAIPs, 0) {
		if kv.Val > uaThresh && data.IPThreats[kv.Key] == nil {
			emptyUAList = append(emptyUAList, kv.Key)
		}
	}

	prefixThresh := cfgInt(cfg, "prefix_threshold", 1000)
	type prefixHit struct {
		prefix string
		hits   int
	}
	var suspectPrefixes []prefixHit
	for _, kv := range topN(data.PrefixCounts, 0) {
		if kv.Val > prefixThresh {
			suspectPrefixes = append(suspectPrefixes, prefixHit{kv.Key, kv.Val})
		}
	}

	// --output-ips
	if outputIPs {
		seen := make(map[string]bool)
		for _, s := range attackIPs {
			if !seen[s.ip] && !isWhitelisted(s.ip, wlNets) && !isProtectedIP(s.ip, data) {
				fmt.Println(s.ip)
				seen[s.ip] = true
			}
		}
		for _, ip := range suspectIPs {
			if !seen[ip] && !isWhitelisted(ip, wlNets) && !isProtectedIP(ip, data) {
				fmt.Println(ip)
				seen[ip] = true
			}
		}
		for _, ip := range emptyUAList {
			if !seen[ip] && !isWhitelisted(ip, wlNets) && !isProtectedIP(ip, data) {
				fmt.Println(ip)
				seen[ip] = true
			}
		}
		return
	}

	if len(wlRaw) > 0 {
		fmt.Printf("\n  %sActive whitelist:%s %s\n", cCyan, cReset, strings.Join(wlRaw, " "))
	}

	// Attack IPs
	header("IPs to ban - Detected attacks")
	if len(attackIPs) > 0 {
		fmt.Printf("  %siptables commands:%s\n\n", cBold, cReset)
		skipWL, skipProt := 0, 0
		for _, s := range attackIPs {
			if isWhitelisted(s.ip, wlNets) {
				skipWL++
				continue
			}
			if isProtectedIP(s.ip, data) {
				skipProt++
				continue
			}
			hits := data.IPCounts[s.ip]
			types := strings.Join(sortedKeys(data.IPThreats[s.ip]), " ")
			cc := geo[s.ip]
			ccStr := ""
			if cc != "" {
				ccStr = cc + " "
			}
			fmt.Printf("  iptables -A INPUT -s %s -j DROP  # %s%s hits [%s] score=%d\n",
				s.ip, ccStr, fmtComma(hits), types, s.score)
		}
		if skipWL > 0 {
			fmt.Printf("\n  %s%d IP(s) skipped (whitelist)%s\n", cCyan, skipWL, cReset)
		}
		if skipProt > 0 {
			fmt.Printf("  %s%d IP(s) skipped (payment/monitoring)%s\n", cCyan, skipProt, cReset)
		}
	} else {
		fmt.Printf("  %sNo attack IPs detected%s\n", cGreen, cReset)
	}

	// Suspect IPs
	header(fmt.Sprintf("IPs to monitor - Suspect volume (> %d req)", thresh))
	if len(suspectIPs) > 0 {
		fmt.Printf("  %sCheck if these IPs are legitimate (monitoring, authorized crawlers)%s\n", cYellow, cReset)
		fmt.Printf("  %sbefore banning. Use: an4log --ip <addr> to profile.%s\n", cYellow, cReset)
		fmt.Printf("\n  %siptables commands:%s\n\n", cBold, cReset)
		for _, ip := range suspectIPs {
			if isWhitelisted(ip, wlNets) || isProtectedIP(ip, data) {
				continue
			}
			hits := data.IPCounts[ip]
			cc := geo[ip]
			ccStr := ""
			if cc != "" {
				ccStr = cc + " "
			}
			fmt.Printf("  iptables -A INPUT -s %s -j DROP  # %s%s hits\n", ip, ccStr, fmtComma(hits))
		}
	} else {
		fmt.Printf("  %sNo suspect IPs by volume%s\n", cGreen, cReset)
	}

	// Empty UA
	header(fmt.Sprintf("IPs without User-Agent (> %d req)", uaThresh))
	if len(emptyUAList) > 0 {
		fmt.Printf("  %sOften bots or scripts. Check before banning.%s\n", cYellow, cReset)
		fmt.Printf("\n  %siptables commands:%s\n\n", cBold, cReset)
		for _, ip := range emptyUAList {
			if isWhitelisted(ip, wlNets) || isProtectedIP(ip, data) {
				continue
			}
			hits := data.EmptyUAIPs[ip]
			cc := geo[ip]
			ccStr := ""
			if cc != "" {
				ccStr = cc + " "
			}
			fmt.Printf("  iptables -A INPUT -s %s -j DROP  # %s%s hits, no UA\n", ip, ccStr, fmtComma(hits))
		}
	} else {
		fmt.Printf("  %sNo significant IPs without UA%s\n", cGreen, cReset)
	}

	// Prefixes
	header(fmt.Sprintf("IP blocks to ban (prefixes > %d req)", prefixThresh))
	if len(suspectPrefixes) > 0 {
		fmt.Printf("  %sWarning: a /16 block = 65536 IPs. Check that these are not%s\n", cYellow, cReset)
		fmt.Printf("  %slegitimate CDN/cloud (Google, Cloudflare, OVH...).%s\n", cYellow, cReset)
		fmt.Printf("\n  %siptables commands:%s\n\n", cBold, cReset)
		for _, ph := range suspectPrefixes {
			if isPrefixWhitelisted(ph.prefix, wlRaw) {
				fmt.Printf("  %s# SKIP %s.0.0/16 (whitelist) - %d hits%s\n", cCyan, ph.prefix, ph.hits, cReset)
				continue
			}
			fmt.Printf("  iptables -A INPUT -s %s.0.0/16 -j DROP  # %s hits\n", ph.prefix, fmtComma(ph.hits))
		}
	} else {
		fmt.Printf("  %sNo suspect IP blocks%s\n", cGreen, cReset)
	}

	// Script + alternatives
	header("Complete script to copy/paste")
	fmt.Printf("  %sReview each rule before execution!%s\n\n", cYellow, cReset)
	fmt.Println("  #!/bin/bash")
	fmt.Printf("  # Generated by an4log v%s - %s\n", version, time.Now().Format("2006-01-02 15:04"))
	fmt.Printf("  # Whitelist: %s\n\n", strings.Join(wlRaw, " "))
	if len(attackIPs) > 0 {
		fmt.Println("  # --- Attack IPs (ban) ---")
		for _, s := range attackIPs {
			if isWhitelisted(s.ip, wlNets) {
				continue
			}
			cc := geo[s.ip]
			ccStr := ""
			if cc != "" {
				ccStr = "  # " + cc
			}
			fmt.Printf("  iptables -A INPUT -s %s -j DROP%s\n", s.ip, ccStr)
		}
		fmt.Println()
	}
	fmt.Println("  # Save rules")
	fmt.Println("  # Debian/Ubuntu : iptables-save > /etc/iptables/rules.v4")
	fmt.Println("  # RHEL/CentOS   : service iptables save")

	header("Recommended alternatives")
	fmt.Printf("  %sfail2ban%s (automatic temporary ban):\n", cBold, cReset)
	fmt.Println("    apt install fail2ban")
	fmt.Printf("  %sipset%s (high-performance mass ban):\n", cBold, cReset)
	fmt.Println("    ipset create an4log_blacklist hash:ip hashsize 4096")
	fmt.Println("    iptables -A INPUT -m set --match-set an4log_blacklist src -j DROP")
}

func cmdVisitors(data *ParseData, cfg Cfg) {
	header("Unique visitors")
	total := data.Total
	unique := len(data.UniqueVisitors)
	uniqueIPs := len(data.IPCounts)
	fmt.Printf("  Total requests      : %s%s%s\n", cBold, fmtComma(total), cReset)
	fmt.Printf("  Unique IPs          : %s%s%s\n", cBold, fmtComma(uniqueIPs), cReset)
	fmt.Printf("  Unique visitors     : %s%s%s  (IP + User-Agent)\n", cBold, fmtComma(unique), cReset)
	if uniqueIPs > 0 {
		ratio := float64(unique) / float64(uniqueIPs)
		fmt.Printf("  Visitor/IP ratio    : %.1f\n", ratio)
	}

	// Per-day unique visitors
	if len(data.DayStats) > 1 {
		fmt.Printf("\n  %sUnique visitors per day:%s\n", cBold, cReset)
		// Rebuild per-day visitors from parsed data — use day+IP as approximation
		type dayVisitors struct {
			key  string
			ips  int
		}
		var days []dayVisitors
		for k, ds := range data.DayStats {
			days = append(days, dayVisitors{k, len(ds.IPs)})
		}
		sort.Slice(days, func(i, j int) bool { return daySortKey(days[i].key).Before(daySortKey(days[j].key)) })
		maxV := 0
		for _, d := range days {
			if d.ips > maxV {
				maxV = d.ips
			}
		}
		for _, d := range days {
			bar := fmtBar(d.ips, maxV, 20)
			fmt.Printf("    %s  %6s  %s\n", d.key, fmtComma(d.ips), bar)
		}
	}
}

func cmdVhost(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d Virtual Hosts", n))
	if len(data.VhostCounts) == 0 {
		fmt.Printf("  %sNo virtual hosts detected (standard format without vhost)%s\n", cYellow, cReset)
		return
	}
	items := topN(data.VhostCounts, n)
	if len(items) == 0 {
		return
	}
	maxVal := items[0].Val
	for _, kv := range items {
		ips := len(data.VhostIPs[kv.Key])
		bytes := data.VhostBytes[kv.Key]
		pct := fmtPct(kv.Val, data.Total)
		bar := fmtBar(kv.Val, maxVal, 15)
		fmt.Printf("  %10s  %s  %s  %s  %4d IPs  %s\n",
			fmtComma(kv.Val), pct, bar, fmtSize(bytes), ips, kv.Key)
	}
}

func percentile(sorted []int, p float64) int {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func cmdResponseTime(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d slowest URIs (response time)", n))

	if len(data.URIResponseTime) == 0 {
		fmt.Printf("  %sNo response time data in logs%s\n", cYellow, cReset)
		fmt.Printf("  Apache: add %%D at end of LogFormat\n")
		fmt.Printf("  Nginx: add $request_time at end of log_format\n")
		return
	}

	// Compute p50, p95, p99, avg per URI
	type uriRT struct {
		uri        string
		avg, p50, p95, p99, count int
	}
	var items []uriRT
	for uri, times := range data.URIResponseTime {
		if len(times) < 3 {
			continue
		}
		sort.Ints(times)
		sum := 0
		for _, t := range times {
			sum += t
		}
		items = append(items, uriRT{
			uri:   uri,
			avg:   sum / len(times),
			p50:   percentile(times, 0.5),
			p95:   percentile(times, 0.95),
			p99:   percentile(times, 0.99),
			count: len(times),
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].p95 > items[j].p95 })

	if len(items) == 0 {
		fmt.Printf("  %sInsufficient data%s\n", cYellow, cReset)
		return
	}

	fmt.Printf("  %6s  %10s  %10s  %10s  %10s  %s\n", "Hits", "Avg(µs)", "P50(µs)", "P95(µs)", "P99(µs)", "URI")
	fmt.Printf("  %s  %s  %s  %s  %s  %s\n",
		strings.Repeat("-", 6), strings.Repeat("-", 10), strings.Repeat("-", 10),
		strings.Repeat("-", 10), strings.Repeat("-", 10), strings.Repeat("-", 30))

	for i, it := range items {
		if i >= n {
			break
		}
		fmt.Printf("  %6s  %10s  %10s  %s%10s%s  %s%10s%s  %s\n",
			fmtComma(it.count),
			fmtComma(it.avg), fmtComma(it.p50),
			cYellow, fmtComma(it.p95), cReset,
			cRed, fmtComma(it.p99), cReset,
			fmtKey(it.uri, 60))
	}
}

func cmdASN(data *ParseData, cfg Cfg) {
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("Top %d networks (ASN)", n))
	dbPath := findASNDB()
	if dbPath == "" {
		warn("GeoLite2-ASN.mmdb not found")
		fmt.Println("    an4log setup-geoip  (also downloads ASN database)")
		return
	}
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		warn(fmt.Sprintf("Error opening ASN: %v", err))
		return
	}
	defer db.Close()

	type asnResult struct {
		ASN  uint   `maxminddb:"autonomous_system_number"`
		Org  string `maxminddb:"autonomous_system_organization"`
	}

	asnHits := make(map[string]int)
	asnIPs := make(map[string]int)
	for ip, hits := range data.IPCounts {
		pip := net.ParseIP(ip)
		if pip == nil {
			continue
		}
		var r asnResult
		key := "??|Unknown"
		if err := db.Lookup(pip, &r); err == nil && r.ASN > 0 {
			key = fmt.Sprintf("AS%d|%s", r.ASN, r.Org)
		}
		asnHits[key] += hits
		asnIPs[key]++
	}

	items := topN(asnHits, n)
	if len(items) == 0 {
		return
	}
	maxVal := items[0].Val
	fmt.Printf("  %10s  %5s  %6s  %s  %s\n", "Hits", "%", "IPs", "", "Network")
	fmt.Println("  " + strings.Repeat("-", 80))
	for _, kv := range items {
		parts := strings.SplitN(kv.Key, "|", 2)
		asn, org := parts[0], parts[1]
		ips := asnIPs[kv.Key]
		pct := fmtPct(kv.Val, data.Total)
		bar := fmtBar(kv.Val, maxVal, 12)
		fmt.Printf("  %10s  %s  %6s  %s  %s (%s)\n",
			fmtComma(kv.Val), pct, fmtComma(ips), bar, org, asn)
	}
}

func cmdWebshell(data *ParseData, cfg Cfg) {
	header("Detected webshell scans")
	if len(data.WebshellIPs) == 0 {
		fmt.Printf("  %sNo webshell scans detected%s\n", cGreen, cReset)
		return
	}
	showTop(data.WebshellIPs, cfgInt(cfg, "top_n", 10), 0, 42)
}

func cmdMalformed(data *ParseData, cfg Cfg) {
	header("Malformed URLs (domain in path)")
	if len(data.MalformedURLs) == 0 {
		fmt.Printf("  %sNo malformed URLs detected%s\n", cGreen, cReset)
		return
	}
	total := 0
	for _, c := range data.MalformedURLs {
		total += c
	}
	fmt.Printf("  %s%s requests with domain in path%s\n", cRed, fmtComma(total), cReset)
	fmt.Printf("  %sLikely cause: bot/preload stripping protocol (https://)%s\n\n", cYellow, cReset)

	n := cfgInt(cfg, "top_n", 10)
	fmt.Printf("  %sTop malformed URIs:%s\n", cBold, cReset)
	showTop(data.MalformedURLs, n, total, 80)
	if len(data.MalformedIPs) > 0 {
		fmt.Printf("\n  %sSource IPs:%s\n", cBold, cReset)
		showTop(data.MalformedIPs, n, 0, 42)
	}
}

func cmdStorm404(data *ParseData, cfg Cfg) {
	thresh := cfgInt(cfg, "burst_threshold", 30)
	n := cfgInt(cfg, "top_n", 10)
	header(fmt.Sprintf("404 storms (> %d 404/min)", thresh))
	type storm struct {
		mkey  string
		count int
	}
	var storms []storm
	for mkey, count := range data.Storm404Minutes {
		if count > thresh {
			storms = append(storms, storm{mkey, count})
		}
	}
	if len(storms) == 0 {
		fmt.Printf("  %sNo 404 storms detected%s\n", cGreen, cReset)
		return
	}
	sort.Slice(storms, func(i, j int) bool { return storms[i].count > storms[j].count })
	fmt.Printf("  %s%d 404 peak(s) detected — risk of PHP exhaustion if 404s go through WordPress%s\n\n",
		cRed, len(storms), cReset)
	for i, s := range storms {
		if i >= n {
			break
		}
		fmt.Printf("  %6s 404/min  %s\n", fmtComma(s.count), s.mkey)
	}
}

func cmdFacets(data *ParseData, cfg Cfg) {
	// Only show URIs with significant facet traffic (> 1% of total or > 100 hits)
	minHits := data.Total / 100
	if minHits < 100 {
		minHits = 100
	}

	type facetEntry struct {
		uri      string
		hits     int
		variants int
		params   map[string]int
		ips      map[string]int
		statuses map[int]int
	}

	var entries []facetEntry
	for uri, hits := range data.FacetURIs {
		if hits < minHits {
			continue
		}
		entries = append(entries, facetEntry{
			uri:      uri,
			hits:     hits,
			variants: data.FacetVariants[uri],
			params:   data.FacetParams[uri],
			ips:      data.FacetIPs[uri],
			statuses: data.FacetStatuses[uri],
		})
	}

	if len(entries) == 0 {
		return
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].hits > entries[j].hits })

	header("Faceted navigation / query strings")

	totalFacet := 0
	for _, e := range entries {
		totalFacet += e.hits
	}
	fmt.Printf("  %s%s requests with query parameters (%s of traffic)%s\n\n",
		cBold, fmtComma(totalFacet), fmtPct(totalFacet, data.Total), cReset)

	n := cfgInt(cfg, "top_n", 10)
	for i, e := range entries {
		if i >= n {
			break
		}
		fmt.Printf("  %s%s%s  %s  %s\n", cCyan, fmtComma(e.hits), cReset, fmtPct(e.hits, data.Total), fmtKey(e.uri, 70))

		// Params
		params := topN(e.params, 5)
		var paramNames []string
		for _, p := range params {
			paramNames = append(paramNames, fmt.Sprintf("%s(%s)", p.Key, fmtComma(p.Val)))
		}
		if len(paramNames) > 0 {
			fmt.Printf("           params: %s\n", strings.Join(paramNames, ", "))
		}

		// Statuses
		statusParts := topNInt(e.statuses, 5)
		var statusStrs []string
		for _, s := range statusParts {
			statusStrs = append(statusStrs, fmt.Sprintf("%d:%s", s.Key, fmtComma(s.Val)))
		}
		if len(statusStrs) > 0 {
			fmt.Printf("           status: %s\n", strings.Join(statusStrs, "  "))
		}

		// Unique IPs
		fmt.Printf("           IPs: %s unique", fmtComma(len(e.ips)))

		// Top 3 IPs
		topIPs := topN(e.ips, 3)
		var ipStrs []string
		for _, tip := range topIPs {
			ipStrs = append(ipStrs, fmt.Sprintf("%s(%s)", fmtKey(tip.Key, 30), fmtComma(tip.Val)))
		}
		if len(ipStrs) > 0 {
			fmt.Printf("  top: %s", strings.Join(ipStrs, ", "))
		}
		fmt.Println()
		fmt.Println()
	}
}

func cmdAll(ctx *CmdCtx) {
	data, cfg := ctx.Data, ctx.Cfg
	cmdSummary(data, cfg)
	cmdClassify(data, cfg)
	if data.GroupBy != "" {
		cmdTimeline(data, cfg)
	}
	cmdIP(data, cfg)
	cmdUA(data, cfg)
	cmdURI(data, cfg)
	cmdPrefix(data, cfg)
	cmdStatus(data, cfg)
	cmdHour(data, cfg)
	cmdCountries(data, cfg)
	if len(data.VhostCounts) > 0 {
		cmdVhost(data, cfg)
	}
	if len(data.URIResponseTime) > 0 {
		cmdResponseTime(data, cfg)
	}
	cmd404(data, cfg)
	cmdCrawlers(data, cfg)
	cmdSuspect(data, cfg)
	cmdEmptyUA(data, cfg)
	cmdVisitors(data, cfg)
	cmdHeavy(data, cfg)
	cmdMethods(data, cfg)
	cmdMinute(data, cfg)
	cmdSlow(data, cfg)
	cmd403(data, cfg)
	cmdBurst(data, cfg)
	cmdASN(data, cfg)

	// Faceted navigation
	if len(data.FacetURIs) > 0 {
		cmdFacets(data, cfg)
	}

	// New detections
	if len(data.MalformedURLs) > 0 {
		cmdMalformed(data, cfg)
	}
	if len(data.Storm404Minutes) > 0 {
		cmdStorm404(data, cfg)
	}

	// Security sections: compact empty ones
	type secCmd struct {
		fn    func(*ParseData, Cfg)
		label string
		empty bool
	}
	secs := []secCmd{
		{cmdWebshell, "Webshell", len(data.WebshellIPs) == 0},
		{cmdScanners, "Scanners", len(data.ScannerUAs) == 0},
		{cmdSQL, "SQL", len(data.ThreatIPs["SQL"]) == 0},
		{cmdXSS, "XSS", len(data.ThreatIPs["XSS"]) == 0},
		{cmdTraversal, "Traversal", len(data.ThreatIPs["TRAVERSAL"]) == 0},
		{cmdWPAttack, "WordPress", len(data.ThreatIPs["WP"]) == 0},
	}

	var emptyLabels []string
	for _, s := range secs {
		if s.empty {
			emptyLabels = append(emptyLabels, s.label)
		} else {
			s.fn(data, cfg)
		}
	}
	if len(emptyLabels) > 0 {
		fmt.Printf("\n  %sNo detection:%s %s\n", cGreen, cReset, strings.Join(emptyLabels, ", "))
	}
}

// ── Helpers ──

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func daySortKey(k string) time.Time {
	t, err := time.Parse("02/Jan/2006", k)
	if err != nil {
		return time.Time{}
	}
	return t
}

func monthSortKey(k string) time.Time {
	t, err := time.Parse("Jan/2006", k)
	if err != nil {
		return time.Time{}
	}
	return t
}

func aggregateMonths(dayStats map[string]*DayStat) map[string]*DayStat {
	months := make(map[string]*DayStat)
	for pkey, ds := range dayStats {
		mkey := pkey[3:] // '10/Mar/2026' -> 'Mar/2026'
		ms := months[mkey]
		if ms == nil {
			ms = &DayStat{IPs: make(map[string]bool)}
			months[mkey] = ms
		}
		ms.Total += ds.Total
		for ip := range ds.IPs {
			ms.IPs[ip] = true
		}
		ms.Threats += ds.Threats
		ms.Bytes += ds.Bytes
		ms.S4xx += ds.S4xx
		ms.S5xx += ds.S5xx
		ms.Bots += ds.Bots
	}
	return months
}
