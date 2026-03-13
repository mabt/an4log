package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var months = map[string]int{
	"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
	"Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

func parseTimestamp(ts string) (time.Time, bool) {
	// "10/Mar/2026:08:18:55 +0100"
	if len(ts) < 20 {
		return time.Time{}, false
	}
	mon, ok := months[ts[3:6]]
	if !ok {
		return time.Time{}, false
	}
	day, e1 := strconv.Atoi(ts[0:2])
	year, e2 := strconv.Atoi(ts[7:11])
	hour, e3 := strconv.Atoi(ts[12:14])
	min, e4 := strconv.Atoi(ts[15:17])
	sec, e5 := strconv.Atoi(ts[18:20])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return time.Time{}, false
	}
	return time.Date(year, time.Month(mon), day, hour, min, sec, 0, time.Local), true
}

func computeCutoff(sinceStr string) (time.Time, bool) {
	now := time.Now()
	if len(sinceStr) >= 2 {
		unit := sinceStr[len(sinceStr)-1]
		if n, err := strconv.Atoi(sinceStr[:len(sinceStr)-1]); err == nil {
			switch unit {
			case 'm':
				return now.Add(-time.Duration(n) * time.Minute), true
			case 'h':
				return now.Add(-time.Duration(n) * time.Hour), true
			case 'd':
				return now.AddDate(0, 0, -n), true
			}
		}
	}
	if t, err := time.Parse("2006-01-02", sinceStr); err == nil {
		return t, true
	}
	warn(fmt.Sprintf("Format --since non reconnu: %s (utiliser: 30m, 2h, 1d, 2026-03-09)", sinceStr))
	return time.Time{}, false
}

func openLog(path string) (io.ReadCloser, error) {
	if path == "-" || path == "/dev/stdin" {
		return io.NopCloser(os.Stdin), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return gz, nil
	}
	return f, nil
}

func newParseData(groupBy string) *ParseData {
	return &ParseData{
		IPCounts: make(map[string]int), UACounts: make(map[string]int),
		URICounts: make(map[string]int), StatusCounts: make(map[int]int),
		IPBytes: make(map[string]int64), PrefixCounts: make(map[string]int),
		HourCounts: make(map[string]int), MinuteCounts: make(map[string]int),
		MethodCounts: make(map[string]int), URI404: make(map[string]int),
		IP403: make(map[string]int), PostIPs: make(map[string]int),
		EmptyUAIPs: make(map[string]int), BotUAs: make(map[string]int),
		IPThreats: make(map[string]map[string]bool), ThreatCounts: make(map[string]int),
		ThreatIPs: make(map[string]map[string]int), ScannerUAs: make(map[string]int),
		UAClassCounts: make(map[string]int), UAClassIPs: make(map[string]map[string]bool),
		IPClasses: make(map[string]map[string]bool), PaymentHits: make(map[string]int),
		IPStatuses: make(map[string]map[int]int), IPBurst: make(map[string]map[string]int),
		IPFirstSeen: make(map[string]time.Time), IPLastSeen: make(map[string]time.Time),
		DayStats: make(map[string]*DayStat), GroupBy: groupBy,
		IPUAs: make(map[string]map[string]bool), IPURIs: make(map[string]map[string]int),
		IPMethods: make(map[string]map[string]int), IPHours: make(map[string]map[string]int),
		UniqueVisitors:  make(map[string]bool),
		VhostCounts:     make(map[string]int),
		VhostIPs:        make(map[string]map[string]bool),
		VhostBytes:      make(map[string]int64),
		URIResponseTime: make(map[string][]int),
		IPResponseTime:  make(map[string][]int),
		ASNData:         make(map[string]string),
	}
}

func parseLog(files []string, cfg Cfg, since, filterIP string, excludeBots bool, groupBy string) *ParseData {
	data := newParseData(groupBy)
	profiling := filterIP != ""

	var cutoff time.Time
	var hasCutoff bool
	if since != "" {
		cutoff, hasCutoff = computeCutoff(since)
	}

	uaCache := make(map[string]*UAInfo)
	topN := cfgInt(cfg, "top_n", 10)
	slowLimit := topN * 2
	showProgress := len(files) > 1

	total := 0
	botCount := 0
	parseErrors := 0

	// Auto-detect vhost format on first parseable line
	hasVhost := false
	vhostDetected := false

	for fi, fpath := range files {
		if showProgress {
			fmt.Fprintf(os.Stderr, "\r  [%d/%d] %-40s", fi+1, len(files), filepath.Base(fpath))
		}
		r, err := openLog(fpath)
		if err != nil {
			warn(fmt.Sprintf("Erreur lecture %s: %v", fpath, err))
			continue
		}
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

		for sc.Scan() {
			line := sc.Text()

			// Auto-detect vhost format on first line
			if !vhostDetected {
				if logRE.MatchString(line) {
					hasVhost = false
				} else if vhostLogRE.MatchString(line) {
					hasVhost = true
				}
				vhostDetected = true
			}

			var ip, tsStr, method, uri, sizeStr, ua, vhost string
			var statusInt int

			if hasVhost {
				m := vhostLogRE.FindStringSubmatch(line)
				if m == nil {
					parseErrors++
					continue
				}
				vhost = m[1]
				ip = m[2]
				tsStr = m[3]
				method = m[4]
				uri = m[5]
				statusInt, _ = strconv.Atoi(m[6])
				sizeStr = m[7]
				ua = m[9]
			} else {
				m := logRE.FindStringSubmatch(line)
				if m == nil {
					parseErrors++
					continue
				}
				ip = m[1]
				tsStr = m[2]
				method = m[3]
				uri = m[4]
				statusInt, _ = strconv.Atoi(m[5])
				sizeStr = m[6]
				ua = m[8]
			}

			status := statusInt
			size := int64(0)
			if sizeStr != "-" {
				size, _ = strconv.ParseInt(sizeStr, 10, 64)
			}

			if filterIP != "" && ip != filterIP {
				continue
			}

			ts, tsOk := parseTimestamp(tsStr)
			if hasCutoff && tsOk && ts.Before(cutoff) {
				continue
			}

			// UA cache
			info := uaCache[ua]
			if info == nil {
				info = &UAInfo{
					IsBot:     botRE.MatchString(ua),
					IsScanner: scannerRE.MatchString(ua),
				}
				for _, cls := range uaClasses {
					if cls.Re.MatchString(ua) {
						info.Class = cls.Name
						break
					}
				}
				uaCache[ua] = info
			}

			if excludeBots && info.IsBot {
				continue
			}

			total++

			// Day stats
			if tsOk && len(tsStr) >= 11 {
				pkey := tsStr[:11]
				ds := data.DayStats[pkey]
				if ds == nil {
					ds = &DayStat{IPs: make(map[string]bool)}
					data.DayStats[pkey] = ds
				}
				ds.Total++
				ds.IPs[ip] = true
				ds.Bytes += size
				if status >= 400 && status < 500 {
					ds.S4xx++
				} else if status >= 500 && status < 600 {
					ds.S5xx++
				}
				if info.IsBot {
					ds.Bots++
				}
			}

			// Basic counts
			data.IPCounts[ip]++
			data.UACounts[ua]++
			data.StatusCounts[status]++
			data.MethodCounts[method]++
			data.IPBytes[ip] += size

			// Unique visitors (IP+UA)
			visitorKey := ip + "|" + ua
			data.UniqueVisitors[visitorKey] = true

			// Virtual host stats
			if vhost != "" {
				data.VhostCounts[vhost]++
				data.VhostBytes[vhost] += size
				ensureStringSet(data.VhostIPs, vhost)[ip] = true
			}

			// Response time (last numeric field on line, in µs)
			if rtm := responseTimeRE.FindStringSubmatch(line); rtm != nil {
				if rt, err := strconv.Atoi(rtm[1]); err == nil && rt > 0 {
					cleanURI2 := uri
					if idx := strings.IndexByte(uri, '?'); idx > 0 {
						cleanURI2 = uri[:idx]
					}
					data.URIResponseTime[cleanURI2] = append(data.URIResponseTime[cleanURI2], rt)
					data.IPResponseTime[ip] = append(data.IPResponseTime[ip], rt)
				}
			}

			// URI (strip query)
			cleanURI := uri
			if idx := strings.IndexByte(uri, '?'); idx > 0 {
				cleanURI = uri[:idx]
			}
			if len(cleanURI) > 1 {
				data.URICounts[cleanURI]++
			}

			// Prefix
			if dot1 := strings.IndexByte(ip, '.'); dot1 > 0 {
				if dot2 := strings.IndexByte(ip[dot1+1:], '.'); dot2 > 0 {
					data.PrefixCounts[ip[:dot1+1+dot2]]++
				}
			}

			// Time
			if tsOk {
				h := tsStr[12:14]
				mkey := tsStr[:17]
				data.HourCounts[h]++
				data.MinuteCounts[mkey]++
				ensureIntMap(data.IPBurst, ip)[mkey]++

				if profiling {
					ensureIntMap(data.IPHours, ip)[h]++
				}

				if prev, ok := data.IPFirstSeen[ip]; !ok || ts.Before(prev) {
					data.IPFirstSeen[ip] = ts
				}
				if prev, ok := data.IPLastSeen[ip]; !ok || ts.After(prev) {
					data.IPLastSeen[ip] = ts
				}
			}

			// Status details
			ensureStatusMap(data.IPStatuses, ip)[status]++
			if status == 404 {
				data.URI404[uri]++
			}
			if status == 403 {
				data.IP403[ip]++
			}
			if method == "POST" {
				data.PostIPs[ip]++
			}
			if ua == "-" || ua == "" {
				data.EmptyUAIPs[ip]++
			}
			if info.IsBot {
				botCount++
				data.BotUAs[ua]++
			}

			// UA classification
			if info.Class != "" {
				data.UAClassCounts[info.Class]++
				ensureStringSet(data.UAClassIPs, info.Class)[ip] = true
				ensureStringSet(data.IPClasses, ip)[info.Class] = true
			} else if ua != "-" && ua != "" && !info.IsBot {
				data.UAClassCounts["HUMAN"]++
			} else if !info.IsBot {
				data.UAClassCounts["UNKNOWN"]++
			}

			// Payment URIs
			if paymentURIRE.MatchString(uri) {
				data.PaymentHits[ip]++
			}

			// IP profile
			if profiling {
				ensureStringSet(data.IPUAs, ip)[ua] = true
				ensureIntMap(data.IPURIs, ip)[uri]++
				ensureIntMap(data.IPMethods, ip)[method]++
			}

			// Threats (URI only, with pre-filter)
			hasThreat := false
			uriLower := strings.ToLower(uri)
			for _, tp := range threatPatterns {
				hintMatch := false
				for _, hint := range tp.Hints {
					if strings.Contains(uriLower, hint) {
						hintMatch = true
						break
					}
				}
				if !hintMatch {
					continue
				}
				if tp.Re.MatchString(uri) {
					if tp.Name == "WP" && status == 200 {
						continue
					}
					ensureStringSet(data.IPThreats, ip)[tp.Name] = true
					data.ThreatCounts[tp.Name]++
					ensureIntMap(data.ThreatIPs, tp.Name)[ip]++
					hasThreat = true
				}
			}

			// Scanners
			if info.IsScanner {
				ensureStringSet(data.IPThreats, ip)["SCAN"] = true
				data.ThreatCounts["SCAN"]++
				data.ScannerUAs[ua]++
				hasThreat = true
			}

			if hasThreat && tsOk && len(tsStr) >= 11 {
				if ds := data.DayStats[tsStr[:11]]; ds != nil {
					ds.Threats++
				}
			}

			// Slow requests
			parts := strings.Fields(line)
			if len(parts) > 0 {
				if t, err := strconv.Atoi(parts[len(parts)-1]); err == nil && t > 0 {
					data.SlowReqs = append(data.SlowReqs, SlowReq{t, uri})
					if len(data.SlowReqs) > slowLimit {
						sort.Slice(data.SlowReqs, func(i, j int) bool {
							return data.SlowReqs[i].Time > data.SlowReqs[j].Time
						})
						data.SlowReqs = data.SlowReqs[:topN]
					}
				}
			}
		}
		r.Close()
	}

	if showProgress {
		fmt.Fprintf(os.Stderr, "\r%60s\r", "")
	}

	data.Total = total
	data.BotCount = botCount
	data.ParseErrors = parseErrors

	sort.Slice(data.SlowReqs, func(i, j int) bool {
		return data.SlowReqs[i].Time > data.SlowReqs[j].Time
	})

	return data
}
