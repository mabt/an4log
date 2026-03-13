package main

import "regexp"

var threatPatterns = []ThreatPattern{
	{"SQL", regexp.MustCompile(`(?i)(union(\s|%20)+select|sleep\(|benchmark\(|information_schema|load_file|EXTRACTVALUE\(|INTO\s+OUTFILE|xp_cmdshell|CONCAT\(0x)`),
		[]string{"union", "sleep(", "benchmark(", "information_schema", "load_file", "extractvalue", "outfile", "xp_cmd", "concat(0x"}},
	{"XSS", regexp.MustCompile(`(?i)(<script|%3cscript|javascript:|onerror=|onload=|alert\(|prompt\(|document\.cookie)`),
		[]string{"script", "javascript:", "onerror", "onload", "alert(", "prompt(", "document.cookie"}},
	{"TRAVERSAL", regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e|%252e)`),
		[]string{"..", "%2e", "%252e"}},
	{"WP", regexp.MustCompile(`(?i)(wp-login\.php|xmlrpc\.php|wp-admin|wp-config|wp-content/uploads/.*\.php|eval-stdin\.php|wp-cron)`),
		[]string{"wp-", "xmlrpc", "eval-stdin"}},
	{"SENSITIVE", regexp.MustCompile(`(?i)(\.env|\.git/config|\.htaccess|\.svn/|\.hg/|phpinfo\.php|server-status|server-info)`),
		[]string{".env", ".git/", ".htaccess", ".svn/", ".hg/", "phpinfo", "server-status", "server-info"}},
}

var scannerRE = regexp.MustCompile(`(?i)(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|nuclei|acunetix|nessus|openvas|burpsuite|zap|w3af|whatweb|wpscan)`)
var botRE = regexp.MustCompile(`(?i)\b(bot|crawl|spider|slurp)\b|(baidu|yandex|semrush|ahrefs|mj12|dotbot|petalbot|bytespider|gptbot|claudebot|bingbot|googlebot)`)

var uaClasses = []UAClass{
	{"PAYMENT", regexp.MustCompile(`(?i)(lyra|payzen|paypal|payplug|stripe|mollie|adyen|braintree|mangopay|hipay|systempay|monetico|mercanet|sips|worldline|checkout\.com)`)},
	{"MONITORING", regexp.MustCompile(`(?i)(uptime[\s_-]?kuma|pingdom|datadog|newrelic|sansec|statuscake|site24x7|hetrixtools|uptimerobot|palo\s*alto|nslookup\.io|turaco|visionheight|nodeping|better[\s_-]?uptime|freshping)`)},
	{"LEGIT_BOT", regexp.MustCompile(`(?i)(googlebot|google-inspectiontool|adsbot-google|google-adwords|apis-google|bingbot|msnbot|slurp|duckduckbot|facebookexternalhit|twitterbot|linkedinbot|slackbot|telegrambot|whatsapp|pinterestbot|qwantbot|applebot|yandexbot)`)},
	{"SEO", regexp.MustCompile(`(?i)(semrush|ahrefs|mj12bot|dotbot|screaming\s*frog|majestic|serpstat|oncrawl|seokicks|sistrix)`)},
	{"AI_BOT", regexp.MustCompile(`(?i)(gptbot|chatgpt|claudebot|anthropic|amazonbot|cohere-ai|perplexity|bytespider|ccbot)`)},
}

var paymentURIRE = regexp.MustCompile(`(?i)(checkout|payment|payzen|paypal|stripe|mollie|ipn|webhook|callback.*pay|/pay/|/order/|payment-information)`)

// Standard Combined Log Format: IP - - [ts] "method uri proto" status size "ref" "ua"
var logRE = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\S+) "([^"]*)" "([^"]*)"`)

// Combined with vhost prefix: vhost:port IP - - [ts] ...
var vhostLogRE = regexp.MustCompile(`^(\S+?)(?::\d+)? (\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\S+) "([^"]*)" "([^"]*)"`)

// Response time at end of line (µs or ms, Apache %D or Nginx $request_time)
var responseTimeRE = regexp.MustCompile(`\s(\d+)$`)

var threatScores = map[string]int{
	"SQL": 10, "XSS": 10, "TRAVERSAL": 8, "SCAN": 8, "WP": 5, "SENSITIVE": 5,
}
