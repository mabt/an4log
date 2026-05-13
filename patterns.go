package main

import "regexp"

var threatPatterns = []ThreatPattern{
	{"SQL", regexp.MustCompile(`(?i)(union(\s|%20)+select|sleep\(|benchmark\(|information_schema|load_file|EXTRACTVALUE\(|INTO\s+OUTFILE|xp_cmdshell|CONCAT\(0x)`),
		[]string{"union", "sleep(", "benchmark(", "information_schema", "load_file", "extractvalue", "outfile", "xp_cmd", "concat(0x"}},
	{"XSS", regexp.MustCompile(`(?i)(<script|%3cscript|javascript:|onerror=|onload=|alert\(|prompt\(|document\.cookie)`),
		[]string{"script", "javascript:", "onerror", "onload", "alert(", "prompt(", "document.cookie"}},
	{"TRAVERSAL", regexp.MustCompile(`(?i)(\.\./\.\./|%2e%2e/%2e%2e|%252e%252e|\.\./(etc|proc|var|tmp|boot|windows|usr|root|home|\.ssh|\.bash))`),
		[]string{"..", "%2e", "%252e"}},
	{"WP", regexp.MustCompile(`(?i)(wp-login\.php|xmlrpc\.php|wp-admin|wp-config|wp-content/uploads/.*\.php|eval-stdin\.php)`),
		[]string{"wp-", "xmlrpc", "eval-stdin"}},
	{"SENSITIVE", regexp.MustCompile(`(?i)(/\.env($|[.\?])|/\.git/(config|HEAD|index|objects|refs)|\.htaccess|/\.svn/|/\.hg/|phpinfo\.php|server-status|server-info)`),
		[]string{"/.env", ".git/", ".htaccess", ".svn/", ".hg/", "phpinfo", "server-status", "server-info"}},
	{"LOG4SHELL", regexp.MustCompile(`(?i)(\$\{jndi:|%24%7bjndi|%2524%257bjndi|\$\{lower:|\$\{upper:|\$\{env:)`),
		[]string{"${jndi", "%24%7bjndi", "%2524%257b", "${lower:", "${upper:", "${env:"}},
	{"CMDI", regexp.MustCompile(`(?i)(;\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|python|perl|php|uname|ping|sleep|echo)\b|%3b\s*(cat|id|whoami|wget|curl|bash))`),
		[]string{";cat", ";ls", ";id", ";who", ";wget", ";curl", ";nc", ";bash", ";sh", ";py", ";php", ";sleep", ";echo", "%3bcat", "%3bid", "%3bwho", "%3bwget", "%3bcurl", "%3bbash"}},
	{"SSRF", regexp.MustCompile(`(?i)(https?://(127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.169\.254|0\.0\.0\.0|localhost)[:/]|/latest/meta-data|/metadata/v\d)`),
		[]string{"127.0.0.1", "169.254.169.254", "192.168.", "0.0.0.0", "localhost", "/latest/meta-data", "/metadata/v"}},
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

// Webshell scan: common backdoor filenames probed by attackers
var webshellRE = regexp.MustCompile(`(?i)/(txets|schallfuns|postnews|alfashell|wso|c99|r57|b374k|mini|shell|madspot|filesman|leaf|indoxploit|adminer)\.php`)
var webshellHints = []string{"txets.", "schallfuns.", "postnews.", "alfashell.", "wso.", "c99.", "r57.", "b374k.", "mini.", "shell.", "madspot.", "filesman.", "leaf.", "indoxploit.", "adminer."}

// Malformed URLs: domain-in-path (bot stripping protocol from absolute URLs)
// Matches: /carrelagesignature.com/wp-content/..., /www.google.com/..., /cdn.example.com/...
var malformedURLRE = regexp.MustCompile(`^/(?:[a-z0-9-]+\.)+(?:com|net|org|io|fr|de|eu|co|uk|info|me|dev|app|cloud|site|online|xyz)/`)

// Login URI pattern for credential stuffing detection
var loginURIRE = regexp.MustCompile(`(?i)(/login|/signin|/auth/|/connect|/wp-login|/admin.*login|/user.*login|/account.*login)`)

var threatScores = map[string]int{
	"SQL": 10, "XSS": 10, "TRAVERSAL": 8, "SCAN": 8, "WP": 5, "SENSITIVE": 5, "WEBSHELL": 8,
	"LOG4SHELL": 10, "CMDI": 10, "SSRF": 10,
}
