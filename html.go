package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net"
	"sort"
	"strings"
	"time"
)

// ── CSS ──

const htmlCSS = `*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  background:#0d1117;color:#e6edf3;line-height:1.5}
.hdr{background:linear-gradient(135deg,#161b22 0%,#0d1117 100%);
  border-bottom:1px solid #21262d;padding:24px 32px}
.hdr h1{font-size:1.3em;color:#58a6ff;font-weight:600;display:flex;align-items:center;gap:8px}
.hdr h1 span{font-size:.6em;color:#484f58;font-weight:400}
.hdr .period{font-size:1.05em;color:#e6edf3;margin-top:6px}
.hdr .meta{font-size:.78em;color:#8b949e;margin-top:3px}
nav{position:sticky;top:0;z-index:100;background:#161b22ee;backdrop-filter:blur(8px);
  border-bottom:1px solid #21262d;padding:0 32px;display:flex;gap:0}
nav a{color:#8b949e;text-decoration:none;padding:10px 14px;font-size:.82em;font-weight:500;
  border-bottom:2px solid transparent;transition:all .15s}
nav a:hover{color:#e6edf3}
nav a.active{color:#58a6ff;border-bottom-color:#58a6ff}
main{max-width:1200px;margin:0 auto;padding:20px 32px 40px}
section{margin-bottom:32px}
h2{color:#e6edf3;font-size:1.05em;font-weight:600;margin:20px 0 10px;
  display:flex;align-items:center;justify-content:space-between}
h3{color:#79c0ff;font-size:.92em;font-weight:600;margin:0 0 8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:12px 0}
.card{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:14px 12px;text-align:center}
.card .v{font-size:1.7em;font-weight:700;color:#58a6ff;font-variant-numeric:tabular-nums}
.card .l{font-size:.7em;color:#8b949e;margin-top:2px;text-transform:uppercase;letter-spacing:.4px}
.card.alert .v{color:#f85149}
.card.ok .v{color:#3fb950}
.btn-group{display:inline-flex;border:1px solid #30363d;border-radius:6px;overflow:hidden}
.btn-group button{background:transparent;border:none;color:#8b949e;padding:5px 12px;
  font-size:.78em;cursor:pointer;border-right:1px solid #30363d;transition:all .12s;font-family:inherit}
.btn-group button:last-child{border-right:none}
.btn-group button:hover{color:#e6edf3;background:#21262d}
.btn-group button.on{background:#58a6ff;color:#fff}
.tl-wrap{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:16px;margin:10px 0}
.tl-chart{display:flex;align-items:flex-end;gap:3px;height:160px;padding:8px 0}
.tl-bar{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;
  height:100%;min-width:14px;cursor:default}
.tl-bar .fill{width:100%;background:linear-gradient(180deg,#58a6ff,#1f6feb);
  border-radius:3px 3px 0 0;min-height:2px;transition:height .3s}
.tl-bar:hover .fill{background:linear-gradient(180deg,#79c0ff,#388bfd)}
.tl-bar .val{font-size:.65em;color:#8b949e;margin-bottom:3px;white-space:nowrap}
.tl-bar .lbl{font-size:.65em;color:#8b949e;margin-top:5px;white-space:nowrap}
.tl-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:8px;margin-top:12px;
  padding-top:12px;border-top:1px solid #21262d;font-size:.78em;text-align:center}
.tl-kpis .v{font-weight:600;color:#e6edf3;font-variant-numeric:tabular-nums}
.tl-kpis .l{color:#8b949e;font-size:.9em}
.tl-kpis .alert{color:#f85149}
.cl-bar{height:30px;border-radius:8px;display:flex;overflow:hidden;margin:10px 0}
.cl-bar div{height:100%;min-width:3px;transition:width .3s;cursor:default}
.cl-bar div:hover{opacity:.8}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;margin:8px 0;font-size:.78em}
.legend span{display:flex;align-items:center;gap:5px}
.legend .dot{width:10px;height:10px;border-radius:3px;flex-shrink:0}
.h-chart{display:grid;grid-template-columns:repeat(24,1fr);gap:3px;align-items:end;height:130px;margin:10px 0}
.h-bar{display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%}
.h-bar .fill{width:100%;background:linear-gradient(180deg,#3fb950,#238636);
  border-radius:2px 2px 0 0;min-height:2px;transition:height .3s}
.h-bar:hover .fill{background:linear-gradient(180deg,#56d364,#2ea043)}
.h-bar .cnt{font-size:.6em;color:#8b949e;margin-bottom:2px}
.h-bar .lbl{font-size:.6em;color:#8b949e;margin-top:4px}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:.82em}
th{background:#161b22;color:#8b949e;text-align:left;padding:8px 10px;border-bottom:2px solid #21262d;
  font-weight:500;cursor:pointer;user-select:none;white-space:nowrap;font-size:.9em}
th:hover{color:#e6edf3}
th .arrow{font-size:.7em;margin-left:3px;opacity:.4}
td{padding:7px 10px;border-bottom:1px solid #21262d;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:#161b2280}
.num{text-align:right;font-variant-numeric:tabular-nums}
.bar-cell{width:100px;overflow:visible}
.bar{height:12px;border-radius:3px;background:#238636;min-width:1px}
.bar.red{background:#f85149}
.bar.yellow{background:#d29922}
.pct{color:#8b949e;font-size:.85em}
.tag{display:inline-block;padding:2px 7px;border-radius:10px;font-size:.68em;font-weight:500;
  margin:1px;white-space:nowrap}
.tag-SQL,.tag-XSS{background:#f8514922;color:#f85149}
.tag-TRAVERSAL,.tag-SCAN{background:#d2992222;color:#d29922}
.tag-WP,.tag-SENSITIVE{background:#23863622;color:#3fb950}
.tag-PAYMENT{background:#58a6ff22;color:#58a6ff}
.tag-MONITORING{background:#58a6ff22;color:#79c0ff}
.tag-LEGIT_BOT{background:#23863622;color:#3fb950}
.tag-SEO{background:#d2992222;color:#d29922}
.tag-AI_BOT{background:#d2992222;color:#d29922}
.tag-HUMAN{background:#e6edf322;color:#e6edf3}
.tag-protected{background:#23863622;color:#3fb950;font-weight:600}
.status{border-radius:10px;padding:14px 18px;margin:10px 0;display:flex;align-items:center;gap:10px}
.status.green{background:#23863615;border:1px solid #23863650}
.status.green .icon{color:#3fb950;font-size:1.3em}
.status.green .text{color:#3fb950;font-weight:500}
.status.red{background:#f8514915;border:1px solid #f8514950}
.status.red .title{color:#f85149;font-weight:600;margin-bottom:6px}
.callout{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px 16px;margin:10px 0;font-size:.82em}
.callout.green{border-color:#23863660}
.callout b{color:#e6edf3}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:800px){.grid2{grid-template-columns:1fr}nav{overflow-x:auto}
  .tl-chart{height:120px}.h-chart{height:100px}main{padding:16px}}
footer{margin-top:32px;padding:14px 0;border-top:1px solid #21262d;color:#484f58;font-size:.78em;text-align:center}
@media print{body{background:#fff;color:#000}.card{border:1px solid #ddd}
  nav{position:static}.btn-group{display:none}.hdr{background:#fff;border-color:#ddd}
  .tl-wrap{background:#fff;border-color:#ddd}h2,h3{color:#000}}`

// ── JS ──

const htmlJS = `function fmtN(n){return n.toLocaleString('fr-FR')}
function fmtSize(n){
  var u=['o','K','M','G','T'];
  for(var i=0;i<u.length;i++){if(Math.abs(n)<1024)return(u[i]==='o'?n:n.toFixed(1))+u[i];n/=1024}
  return n.toFixed(1)+'P';
}
function setTL(mode){
  tlMode=mode;
  document.querySelectorAll('.tl-btn').forEach(function(b){b.classList.toggle('on',b.dataset.m===mode)});
  renderTL();
}
function renderTL(){
  var src=TL[tlMode],chart=document.getElementById('tl-chart'),kpis=document.getElementById('tl-kpis');
  if(!src||!src.length){chart.innerHTML='<div style="color:#8b949e;padding:20px">Aucune donnee</div>';kpis.innerHTML='';return}
  var mx=Math.max.apply(null,src.map(function(d){return d.total}))||1;
  chart.innerHTML=src.map(function(d){
    var h=Math.max(d.total/mx*100,2);
    return '<div class="tl-bar"><div class="val">'+fmtN(d.total)+'</div>'+
      '<div class="fill" style="height:'+h.toFixed(1)+'%" title="'+d.label+': '+fmtN(d.total)+' req, '+
      fmtN(d.ips)+' IPs, '+fmtN(d.threats)+' menaces"></div>'+
      '<div class="lbl">'+d.label+'</div></div>';
  }).join('');
  var t={total:0,ips:0,threats:0,s4xx:0,s5xx:0,bytes:0,bots:0};
  src.forEach(function(d){t.total+=d.total;t.ips+=d.ips;t.threats+=d.threats;
    t.s4xx+=d.s4xx;t.s5xx+=d.s5xx;t.bytes+=d.bytes;t.bots+=d.bots});
  kpis.innerHTML='<div><div class="v">'+fmtN(t.total)+'</div><div class="l">Requetes</div></div>'+
    '<div><div class="v">'+fmtN(t.ips)+'</div><div class="l">IPs</div></div>'+
    '<div><div class="v'+(t.threats?' alert':'')+'">'+(t.threats?fmtN(t.threats):'0')+'</div><div class="l">Menaces</div></div>'+
    '<div><div class="v">'+fmtN(t.s4xx)+'</div><div class="l">4xx</div></div>'+
    '<div><div class="v'+(t.s5xx?' alert':'')+'">'+(t.s5xx?fmtN(t.s5xx):'0')+'</div><div class="l">5xx</div></div>'+
    '<div><div class="v">'+fmtSize(t.bytes)+'</div><div class="l">Volume</div></div>'+
    '<div><div class="v">'+fmtN(t.bots)+'</div><div class="l">Bots</div></div>';
}
function sortTbl(th,col){
  var tbl=th.closest('table'),tbody=tbl.tBodies[0],rows=Array.from(tbody.rows);
  var dir=th.dataset.dir==='a'?'d':'a';
  tbl.querySelectorAll('th').forEach(function(t){t.dataset.dir='';t.querySelector('.arrow').textContent='\u2195'});
  th.dataset.dir=dir;th.querySelector('.arrow').textContent=dir==='a'?'\u2191':'\u2193';
  rows.sort(function(a,b){
    var va=a.cells[col].dataset.v,vb=b.cells[col].dataset.v;
    if(va!==undefined&&vb!==undefined){va=parseFloat(va);vb=parseFloat(vb);return dir==='a'?va-vb:vb-va}
    va=a.cells[col].textContent;vb=b.cells[col].textContent;
    return dir==='a'?va.localeCompare(vb):vb.localeCompare(va);
  });
  rows.forEach(function(r){tbody.appendChild(r)});
}
document.addEventListener('DOMContentLoaded',function(){
  renderTL();
  var secs=document.querySelectorAll('section[id]');
  var navLinks=document.querySelectorAll('nav a');
  function updateNav(){
    var y=window.scrollY+80;
    secs.forEach(function(s){
      if(s.offsetTop<=y&&s.offsetTop+s.offsetHeight>y){
        navLinks.forEach(function(a){a.classList.toggle('active',a.getAttribute('href')==='#'+s.id)});
      }
    });
  }
  window.addEventListener('scroll',updateNav,{passive:true});
  updateNav();
  navLinks.forEach(function(a){a.addEventListener('click',function(e){
    e.preventDefault();var t=document.querySelector(this.getAttribute('href'));
    if(t)t.scrollIntoView({behavior:'smooth',block:'start'});
  })});
});`

// ── HTML helpers ──

func esc(s string) string {
	return html.EscapeString(s)
}

func barHTML(val, maxVal int, cssClass string) string {
	if maxVal <= 0 {
		return ""
	}
	pct := float64(val) / float64(maxVal) * 100
	if pct < 0.5 {
		pct = 0.5
	}
	cls := ""
	if cssClass != "" {
		cls = " " + cssClass
	}
	return fmt.Sprintf(`<div class="bar%s" style="width:%.1f%%"></div>`, cls, pct)
}

func htmlTable(headers []string, rows [][]string, barValues []int, barMax int, barClass string) string {
	var b strings.Builder
	b.WriteString("<table><thead><tr>")
	for i, th := range headers {
		cls := ""
		if i == 0 {
			cls = ` class="num"`
		}
		fmt.Fprintf(&b, `<th%s onclick="sortTbl(this,%d)">%s<span class="arrow">↕</span></th>`, cls, i, esc(th))
	}
	if barValues != nil {
		b.WriteString(`<th class="bar-cell"></th>`)
	}
	b.WriteString("</tr></thead><tbody>")

	for idx, row := range rows {
		b.WriteString("<tr>")
		for i, td := range row {
			cls := ""
			if i == 0 {
				cls = ` class="num"`
			}
			dv := ""
			if barValues != nil && i == 0 && idx < len(barValues) {
				dv = fmt.Sprintf(` data-v="%d"`, barValues[idx])
			}
			fmt.Fprintf(&b, "<td%s%s>%s</td>", cls, dv, td)
		}
		if barValues != nil && barMax > 0 {
			val := 0
			if idx < len(barValues) {
				val = barValues[idx]
			}
			fmt.Fprintf(&b, `<td class="bar-cell">%s</td>`, barHTML(val, barMax, barClass))
		}
		b.WriteString("</tr>")
	}
	b.WriteString("</tbody></table>")
	return b.String()
}

func fmtDateRange(data *ParseData) (string, string) {
	if len(data.IPFirstSeen) == 0 {
		return "", ""
	}
	var first, last time.Time
	for _, t := range data.IPFirstSeen {
		if first.IsZero() || t.Before(first) {
			first = t
		}
	}
	for _, t := range data.IPLastSeen {
		if last.IsZero() || t.After(last) {
			last = t
		}
	}
	return first.Format("02/01/2006 15:04"), last.Format("02/01/2006 15:04")
}

func fmtCommaHTML(n int) string {
	return fmtComma(n)
}

// ── Timeline JSON structures ──

type tlEntry struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Total   int    `json:"total"`
	IPs     int    `json:"ips"`
	Threats int    `json:"threats"`
	S4xx    int    `json:"s4xx"`
	S5xx    int    `json:"s5xx"`
	Bytes   int64  `json:"bytes"`
	Bots    int    `json:"bots"`
}

type tlData struct {
	Day   []tlEntry `json:"day"`
	Month []tlEntry `json:"month"`
	All   []tlEntry `json:"all"`
}

// ── Main generator ──

func generateHTMLReport(data *ParseData, cfg Cfg, files []string, elapsed float64,
	geo map[string]string, wlRaw []string, wlNets []net.IPNet, geoFull map[string][2]string) string {

	total := data.Total
	uniqueIPs := len(data.IPCounts)
	var totalBytes int64
	for _, b := range data.IPBytes {
		totalBytes += b
	}
	bots := data.BotCount
	var s4xx, s5xx int
	for s, c := range data.StatusCounts {
		if s >= 400 && s < 500 {
			s4xx += c
		} else if s >= 500 && s < 600 {
			s5xx += c
		}
	}
	threatsTotal := 0
	for _, c := range data.ThreatCounts {
		threatsTotal += c
	}
	suspectThresh := cfgInt(cfg, "suspect_threshold", 500)
	suspectCount := 0
	for _, c := range data.IPCounts {
		if c > suspectThresh {
			suspectCount++
		}
	}
	now := time.Now()
	n := cfgInt(cfg, "top_n", 10)
	dateFrom, dateTo := fmtDateRange(data)

	// Unique days
	uniqueDays := make(map[string]bool)
	for _, t := range data.IPFirstSeen {
		uniqueDays[t.Format("2006-01-02")] = true
	}
	for _, t := range data.IPLastSeen {
		uniqueDays[t.Format("2006-01-02")] = true
	}
	nDays := len(uniqueDays)
	daysStr := fmt.Sprintf("%d jour", nDays)
	if nDays > 1 {
		daysStr += "s"
	}

	// Timeline JSON
	sortedDayKeys := make([]string, 0, len(data.DayStats))
	for k := range data.DayStats {
		sortedDayKeys = append(sortedDayKeys, k)
	}
	sort.Slice(sortedDayKeys, func(i, j int) bool {
		return daySortKey(sortedDayKeys[i]).Before(daySortKey(sortedDayKeys[j]))
	})

	dayJSON := make([]tlEntry, 0, len(sortedDayKeys))
	for _, pkey := range sortedDayKeys {
		ds := data.DayStats[pkey]
		label := pkey
		if t := daySortKey(pkey); !t.IsZero() {
			label = t.Format("02/01")
		}
		dayJSON = append(dayJSON, tlEntry{
			Key: pkey, Label: label, Total: ds.Total,
			IPs: len(ds.IPs), Threats: ds.Threats,
			S4xx: ds.S4xx, S5xx: ds.S5xx, Bytes: ds.Bytes, Bots: ds.Bots,
		})
	}

	monthStats := aggregateMonths(data.DayStats)
	sortedMonthKeys := make([]string, 0, len(monthStats))
	for k := range monthStats {
		sortedMonthKeys = append(sortedMonthKeys, k)
	}
	sort.Slice(sortedMonthKeys, func(i, j int) bool {
		return monthSortKey(sortedMonthKeys[i]).Before(monthSortKey(sortedMonthKeys[j]))
	})

	monthJSON := make([]tlEntry, 0, len(sortedMonthKeys))
	for _, mkey := range sortedMonthKeys {
		ms := monthStats[mkey]
		label := mkey
		if t := monthSortKey(mkey); !t.IsZero() {
			label = t.Format("01/2006")
		}
		monthJSON = append(monthJSON, tlEntry{
			Key: mkey, Label: label, Total: ms.Total,
			IPs: len(ms.IPs), Threats: ms.Threats,
			S4xx: ms.S4xx, S5xx: ms.S5xx, Bytes: ms.Bytes, Bots: ms.Bots,
		})
	}

	allJSON := []tlEntry{{
		Key: "all", Label: "Total", Total: total, IPs: uniqueIPs,
		Threats: threatsTotal, S4xx: s4xx, S5xx: s5xx, Bytes: totalBytes, Bots: bots,
	}}

	tlJSON, _ := json.Marshal(tlData{Day: dayJSON, Month: monthJSON, All: allJSON})

	// Protected IPs
	protectedIPs := make(map[string]bool)
	for _, cls := range []string{"PAYMENT", "MONITORING"} {
		for ip := range data.UAClassIPs[cls] {
			protectedIPs[ip] = true
		}
	}

	// Build HTML
	var p strings.Builder

	// Head
	fmt.Fprintf(&p, `<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rapport an4log — %s &rarr; %s</title>
<style>%s</style></head><body>`, esc(dateFrom), esc(dateTo), htmlCSS)

	// Header
	filesStr := "fichier"
	if len(files) > 1 {
		filesStr = "fichiers"
	}
	fmt.Fprintf(&p, `<div class="hdr">
<h1>an4log <span>v%s</span></h1>
<div class="period">%s &rarr; %s &nbsp;&middot;&nbsp; %s</div>
<div class="meta">%d %s &middot; Parse en %.2fs &middot; Genere le %s</div>
</div>`, version, esc(dateFrom), esc(dateTo), daysStr,
		len(files), filesStr, elapsed, now.Format("02/01/2006 a 15:04"))

	// Nav
	p.WriteString(`<nav><a href="#overview">Vue d'ensemble</a><a href="#traffic">Trafic</a>` +
		`<a href="#security">Securite</a><a href="#details">Details</a></nav>`)

	p.WriteString("<main>")

	// ═══════════ SECTION 1: Vue d'ensemble ═══════════
	p.WriteString(`<section id="overview">`)

	// KPI cards
	botPct := 0
	if total > 0 {
		botPct = bots * 100 / total
	}
	p.WriteString(`<div class="cards">`)

	type card struct {
		val, label, extra string
	}
	cards := []card{
		{fmtCommaHTML(total), "Requetes", ""},
		{fmtCommaHTML(uniqueIPs), "IPs uniques", ""},
		{fmtSize(totalBytes), "Volume", ""},
		{fmtCommaHTML(bots), fmt.Sprintf("Bots (%d%%)", botPct), ""},
	}
	extra4xx := ""
	if total > 0 && s4xx > total/5 {
		extra4xx = "alert"
	}
	cards = append(cards, card{fmtCommaHTML(s4xx), "Erreurs 4xx", extra4xx})
	extra5xx := "ok"
	if s5xx > 0 {
		extra5xx = "alert"
	}
	cards = append(cards, card{fmtCommaHTML(s5xx), "Erreurs 5xx", extra5xx})
	if threatsTotal > 0 {
		cards = append(cards, card{fmtCommaHTML(threatsTotal), "Menaces", "alert"})
	}
	if suspectCount > 0 {
		cards = append(cards, card{fmt.Sprintf("%d", suspectCount), "IPs suspectes", "alert"})
	}
	for _, c := range cards {
		cls := ""
		if c.extra != "" {
			cls = " " + c.extra
		}
		fmt.Fprintf(&p, `<div class="card%s"><div class="v">%s</div><div class="l">%s</div></div>`, cls, c.val, c.label)
	}
	p.WriteString("</div>")

	// Timeline
	if len(data.DayStats) > 0 {
		defaultMode := "day"
		if nDays > 90 {
			defaultMode = "month"
		}
		dayOn, monthOn := "", ""
		if defaultMode == "day" {
			dayOn = " on"
		} else {
			monthOn = " on"
		}
		fmt.Fprintf(&p, `<h2>Evolution
<div class="btn-group">
<button class="tl-btn%s" data-m="day" onclick="setTL('day')">Jour</button>
<button class="tl-btn%s" data-m="month" onclick="setTL('month')">Mois</button>
<button class="tl-btn" data-m="all" onclick="setTL('all')">Tout</button>
</div></h2>
<div class="tl-wrap">
<div class="tl-chart" id="tl-chart"></div>
<div class="tl-kpis" id="tl-kpis"></div>
</div>`, dayOn, monthOn)
	}

	// Classification
	classColors := map[string]string{
		"HUMAN": "#c9d1d9", "PAYMENT": "#58a6ff", "MONITORING": "#79c0ff",
		"LEGIT_BOT": "#3fb950", "SEO": "#d29922", "AI_BOT": "#e3b341", "UNKNOWN": "#484f58",
	}
	classLabels := map[string]string{
		"HUMAN": "Humain", "PAYMENT": "Paiement", "MONITORING": "Monitoring",
		"LEGIT_BOT": "Bots legitimes", "SEO": "SEO", "AI_BOT": "IA", "UNKNOWN": "Inconnu",
	}
	classOrder := []string{"HUMAN", "PAYMENT", "MONITORING", "LEGIT_BOT", "SEO", "AI_BOT", "UNKNOWN"}

	p.WriteString("<h2>Classification du trafic</h2>")
	p.WriteString(`<div class="cl-bar">`)
	for _, key := range classOrder {
		count := data.UAClassCounts[key]
		if count > 0 && total > 0 {
			pct := float64(count) / float64(total) * 100
			if pct < 0.5 {
				pct = 0.5
			}
			fmt.Fprintf(&p, `<div style="width:%.1f%%;background:%s" title="%s: %s (%.1f%%)"></div>`,
				pct, classColors[key], classLabels[key], fmtCommaHTML(count), float64(count)/float64(total)*100)
		}
	}
	p.WriteString(`</div><div class="legend">`)
	for _, key := range classOrder {
		count := data.UAClassCounts[key]
		if count > 0 {
			ips := len(data.UAClassIPs[key])
			pct := float64(0)
			if total > 0 {
				pct = float64(count) / float64(total) * 100
			}
			ipStr := ""
			if ips > 0 {
				ipStr = fmt.Sprintf(" &mdash; %d IPs", ips)
			}
			fmt.Fprintf(&p, `<span><span class="dot" style="background:%s"></span>%s: %s (%.1f%%)%s</span>`,
				classColors[key], classLabels[key], fmtCommaHTML(count), pct, ipStr)
		}
	}
	p.WriteString("</div></section>")

	// ═══════════ SECTION 2: Trafic ═══════════
	p.WriteString(`<section id="traffic">`)

	// Hours chart
	p.WriteString("<h2>Trafic par heure</h2>")
	maxH := 0
	for _, c := range data.HourCounts {
		if c > maxH {
			maxH = c
		}
	}
	if maxH == 0 {
		maxH = 1
	}
	p.WriteString(`<div class="h-chart">`)
	for h := 0; h < 24; h++ {
		hk := fmt.Sprintf("%02d", h)
		count := data.HourCounts[hk]
		height := 2
		if maxH > 0 {
			height = count * 100 / maxH
		}
		if height < 2 {
			height = 2
		}
		cntLabel := ""
		if count > 0 {
			cntLabel = fmtCommaHTML(count)
		}
		fmt.Fprintf(&p, `<div class="h-bar"><div class="cnt">%s</div>`+
			`<div class="fill" style="height:%dpx" title="%sh: %s req"></div>`+
			`<div class="lbl">%sh</div></div>`, cntLabel, height, hk, fmtCommaHTML(count), hk)
	}
	p.WriteString("</div>")

	// Top IPs
	fmt.Fprintf(&p, "<h2>Top %d IPs</h2>", n)
	ipItems := topN(data.IPCounts, n)
	if len(ipItems) > 0 {
		maxV := ipItems[0].Val
		var rows [][]string
		var barVals []int
		for _, kv := range ipItems {
			ip := kv.Key
			tags := ""
			if classes := sortedKeys(data.IPClasses[ip]); len(classes) > 0 {
				for _, t := range classes {
					tags += fmt.Sprintf(`<span class="tag tag-%s">%s</span>`, t, t)
				}
			}
			if isProtectedIP(ip, data) {
				tags += ` <span class="tag tag-protected">PROTEGE</span>`
			}
			cc := esc(geo[ip])
			ipCell := esc(ip)
			if cc != "" {
				ipCell = cc + " " + esc(ip)
			}
			pct := float64(0)
			if total > 0 {
				pct = float64(kv.Val) / float64(total) * 100
			}
			rows = append(rows, []string{
				fmtCommaHTML(kv.Val),
				fmt.Sprintf(`<span class="pct">%.1f%%</span>`, pct),
				ipCell, tags,
			})
			barVals = append(barVals, kv.Val)
		}
		p.WriteString(htmlTable([]string{"Hits", "%", "IP", "Type"}, rows, barVals, maxV, ""))
	}

	// Top countries
	if len(geoFull) > 0 {
		countryIPs := make(map[string]int)
		countryHits := make(map[string]int)
		for ip, hits := range data.IPCounts {
			info := geoFull[ip]
			cc := info[0]
			name := info[1]
			if cc == "" {
				cc = "??"
				name = "Inconnu"
			}
			key := cc + "|" + name
			countryIPs[key]++
			countryHits[key] += hits
		}
		fmt.Fprintf(&p, "<h2>Top %d pays</h2>", n)
		items := topN(countryHits, n)
		if len(items) > 0 {
			maxV := items[0].Val
			var rows [][]string
			var barVals []int
			for _, kv := range items {
				parts := strings.SplitN(kv.Key, "|", 2)
				iso, name := parts[0], parts[1]
				ipsCount := countryIPs[kv.Key]
				pct := float64(0)
				if total > 0 {
					pct = float64(kv.Val) / float64(total) * 100
				}
				rows = append(rows, []string{
					fmtCommaHTML(kv.Val),
					fmt.Sprintf(`<span class="pct">%.1f%%</span>`, pct),
					fmtCommaHTML(ipsCount),
					esc(iso), esc(name),
				})
				barVals = append(barVals, kv.Val)
			}
			p.WriteString(htmlTable([]string{"Hits", "%", "IPs", "Code", "Pays"}, rows, barVals, maxV, ""))
		}
	}

	// HTTP codes + URIs side by side
	p.WriteString(`<div class="grid2"><div>`)
	p.WriteString("<h3>Codes HTTP</h3>")
	statusItems := topNInt(data.StatusCounts, n)
	if len(statusItems) > 0 {
		maxV := statusItems[0].Val
		var rows [][]string
		var barVals []int
		for _, kv := range statusItems {
			pct := float64(0)
			if total > 0 {
				pct = float64(kv.Val) / float64(total) * 100
			}
			rows = append(rows, []string{
				fmtCommaHTML(kv.Val),
				fmt.Sprintf(`<span class="pct">%.1f%%</span>`, pct),
				fmt.Sprintf("%d", kv.Key),
			})
			barVals = append(barVals, kv.Val)
		}
		p.WriteString(htmlTable([]string{"Hits", "%", "Code"}, rows, barVals, maxV, ""))
	}
	p.WriteString("</div><div>")
	p.WriteString("<h3>Top URIs</h3>")
	uriItems := topN(data.URICounts, n)
	if len(uriItems) > 0 {
		maxV := uriItems[0].Val
		var rows [][]string
		var barVals []int
		for _, kv := range uriItems {
			pct := float64(0)
			if total > 0 {
				pct = float64(kv.Val) / float64(total) * 100
			}
			rows = append(rows, []string{
				fmtCommaHTML(kv.Val),
				fmt.Sprintf(`<span class="pct">%.1f%%</span>`, pct),
				fmt.Sprintf(`<span title="%s">%s</span>`, esc(kv.Key), esc(kv.Key)),
			})
			barVals = append(barVals, kv.Val)
		}
		p.WriteString(htmlTable([]string{"Hits", "%", "URI"}, rows, barVals, maxV, ""))
	}
	p.WriteString("</div></div></section>")

	// ═══════════ SECTION 3: Securite ═══════════
	p.WriteString(`<section id="security">`)
	p.WriteString("<h2>Securite</h2>")

	if threatsTotal > 0 || len(data.IPThreats) > 0 {
		threatLabels := map[string]string{
			"SQL": "SQL Injection", "XSS": "XSS", "TRAVERSAL": "Path Traversal",
			"SCAN": "Scanners", "WP": "WordPress", "SENSITIVE": "Fichiers sensibles",
		}
		threatOrder := []string{"SQL", "XSS", "TRAVERSAL", "SCAN", "WP", "SENSITIVE"}

		p.WriteString(`<div class="status red"><div>`)
		plural := ""
		if threatsTotal > 1 {
			plural = "s"
		}
		fmt.Fprintf(&p, `<div class="title">%s menace%s detectee%s</div>`,
			fmtCommaHTML(threatsTotal), plural, plural)

		for _, ttype := range threatOrder {
			tcount := data.ThreatCounts[ttype]
			if tcount <= 0 {
				continue
			}
			label := threatLabels[ttype]
			// Top 3 source IPs
			topSrc := topN(data.ThreatIPs[ttype], 3)
			topStr := ""
			if len(topSrc) > 0 {
				var ips []string
				for _, kv := range topSrc {
					ips = append(ips, kv.Key)
				}
				topStr = " &mdash; " + strings.Join(ips, ", ")
			}
			fmt.Fprintf(&p, `<span class="tag tag-%s">%s</span> %s: <b>%s</b>%s<br>`,
				ttype, ttype, esc(label), fmtCommaHTML(tcount), topStr)
		}
		p.WriteString("</div></div>")

		// IPs to ban
		type scoredIP struct {
			ip    string
			score int
		}
		var attackIPs []scoredIP
		for ip := range data.IPThreats {
			if !isWhitelisted(ip, wlNets) && !isProtectedIP(ip, data) {
				attackIPs = append(attackIPs, scoredIP{ip, ipScore(ip, data, cfg)})
			}
		}
		sort.Slice(attackIPs, func(i, j int) bool { return attackIPs[i].score > attackIPs[j].score })

		if len(attackIPs) > 0 {
			fmt.Fprintf(&p, `<h3 style="color:#f85149;margin-top:16px">IPs a bannir (%d)</h3>`, len(attackIPs))
			limit := n * 2
			if limit > len(attackIPs) {
				limit = len(attackIPs)
			}
			var rows [][]string
			var barVals []int
			maxScore := 0
			for _, aip := range attackIPs[:limit] {
				if aip.score > maxScore {
					maxScore = aip.score
				}
			}
			for _, aip := range attackIPs[:limit] {
				hits := data.IPCounts[aip.ip]
				tags := ""
				for _, t := range sortedKeys(data.IPThreats[aip.ip]) {
					tags += fmt.Sprintf(`<span class="tag tag-%s">%s</span>`, t, t)
				}
				cc := esc(geo[aip.ip])
				rows = append(rows, []string{
					fmt.Sprintf("%d", aip.score),
					fmtCommaHTML(hits),
					cc,
					esc(aip.ip),
					tags,
					fmt.Sprintf(`<code style="font-size:.8em;color:#8b949e">iptables -A INPUT -s %s -j DROP</code>`, esc(aip.ip)),
				})
				barVals = append(barVals, aip.score)
			}
			p.WriteString(htmlTable([]string{"Score", "Hits", "Pays", "IP", "Types", "Commande"}, rows, barVals, maxScore, "red"))
		}
	} else {
		p.WriteString(`<div class="status green"><div class="icon">&#10003;</div>` +
			`<div class="text">Aucune menace detectee</div></div>`)
	}

	// Protected IPs
	if len(protectedIPs) > 0 {
		p.WriteString(`<h3 style="margin-top:16px">IPs protegees</h3>`)
		sortedProt := make([]string, 0, len(protectedIPs))
		for ip := range protectedIPs {
			sortedProt = append(sortedProt, ip)
		}
		sort.Slice(sortedProt, func(i, j int) bool {
			return data.IPCounts[sortedProt[i]] > data.IPCounts[sortedProt[j]]
		})
		var protLines []string
		for _, ip := range sortedProt {
			hits := data.IPCounts[ip]
			tags := ""
			for _, t := range sortedKeys(data.IPClasses[ip]) {
				tags += fmt.Sprintf(` <span class="tag tag-%s">%s</span>`, t, t)
			}
			protLines = append(protLines, fmt.Sprintf("%s &mdash; %s hits &mdash;%s", esc(ip), fmtCommaHTML(hits), tags))
		}
		fmt.Fprintf(&p, `<div class="callout green"><b>Ces IPs ne sont jamais proposees au ban :</b><br>%s</div>`,
			strings.Join(protLines, "<br>"))
	}
	p.WriteString("</section>")

	// ═══════════ SECTION 4: Details ═══════════
	p.WriteString(`<section id="details"><div class="grid2"><div>`)

	// Bots
	p.WriteString("<h3>Bots / Crawlers</h3>")
	botItems := topN(data.BotUAs, n)
	if len(botItems) > 0 {
		maxV := botItems[0].Val
		var rows [][]string
		var barVals []int
		for _, kv := range botItems {
			truncUA := kv.Key
			if len(truncUA) > 80 {
				truncUA = truncUA[:80]
			}
			rows = append(rows, []string{
				fmtCommaHTML(kv.Val),
				fmt.Sprintf(`<span title="%s">%s</span>`, esc(kv.Key), esc(truncUA)),
			})
			barVals = append(barVals, kv.Val)
		}
		p.WriteString(htmlTable([]string{"Hits", "User-Agent"}, rows, barVals, maxV, ""))
	} else {
		p.WriteString(`<div style="color:#8b949e;padding:12px">Aucun bot detecte</div>`)
	}

	p.WriteString("</div><div>")

	// 404s
	p.WriteString("<h3>Top erreurs 404</h3>")
	items404 := topN(data.URI404, n)
	if len(items404) > 0 {
		maxV := items404[0].Val
		var rows [][]string
		var barVals []int
		for _, kv := range items404 {
			rows = append(rows, []string{
				fmtCommaHTML(kv.Val),
				fmt.Sprintf(`<span title="%s">%s</span>`, esc(kv.Key), esc(kv.Key)),
			})
			barVals = append(barVals, kv.Val)
		}
		p.WriteString(htmlTable([]string{"Hits", "URI"}, rows, barVals, maxV, "yellow"))
	} else {
		p.WriteString(`<div style="color:#8b949e;padding:12px">Aucune erreur 404</div>`)
	}

	p.WriteString("</div></div></section>")
	p.WriteString("</main>")

	// Footer
	fmt.Fprintf(&p, `<footer>an4log v%s &middot; Genere le %s</footer>`, version, now.Format("02/01/2006 a 15:04"))

	// JavaScript
	defaultMode := "day"
	if nDays > 90 {
		defaultMode = "month"
	}
	fmt.Fprintf(&p, `<script>var TL=%s;var tlMode="%s";`, string(tlJSON), defaultMode)
	p.WriteString(htmlJS)
	p.WriteString("</script></body></html>")

	return p.String()
}
