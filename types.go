package main

import (
	"net"
	"regexp"
	"time"
)

var version = "3.1.0"

// ── Data structures ──

type ParseData struct {
	Total        int
	ParseErrors  int
	IPCounts     map[string]int
	UACounts     map[string]int
	URICounts    map[string]int
	StatusCounts map[int]int
	IPBytes      map[string]int64
	PrefixCounts map[string]int
	HourCounts   map[string]int
	MinuteCounts map[string]int
	MethodCounts map[string]int
	URI404       map[string]int
	IP403        map[string]int
	PostIPs      map[string]int
	EmptyUAIPs   map[string]int
	BotUAs       map[string]int
	BotCount     int
	IPThreats    map[string]map[string]bool // ip -> set of threat types
	ThreatCounts map[string]int
	ThreatIPs    map[string]map[string]int // threat_type -> ip -> count
	ScannerUAs   map[string]int
	UAClassCounts map[string]int
	UAClassIPs   map[string]map[string]bool // class -> set of IPs
	IPClasses    map[string]map[string]bool // ip -> set of classes
	PaymentHits  map[string]int
	IPStatuses   map[string]map[int]int
	IPUAs        map[string]map[string]bool
	IPURIs       map[string]map[string]int
	IPMethods    map[string]map[string]int
	IPHours      map[string]map[string]int
	IPBurst      map[string]map[string]int
	IPFirstSeen  map[string]time.Time
	IPLastSeen   map[string]time.Time
	SlowReqs        []SlowReq
	DayStats        map[string]*DayStat
	GroupBy         string
	UniqueVisitors  map[string]bool   // IP+UA combo for unique visitor counting
	VhostCounts     map[string]int    // virtual host -> hits
	VhostIPs        map[string]map[string]bool // vhost -> set of IPs
	VhostBytes      map[string]int64  // vhost -> bytes
	URIResponseTime map[string][]int  // URI -> response times (µs)
	IPResponseTime  map[string][]int  // IP -> response times (µs)
	ASNData         map[string]string // ip -> "AS1234 Name"
}

type DayStat struct {
	Total   int
	IPs     map[string]bool
	Threats int
	Bytes   int64
	S4xx    int
	S5xx    int
	Bots    int
}

type SlowReq struct {
	Time int
	URI  string
}

type UAInfo struct {
	IsBot     bool
	IsScanner bool
	Class     string
}

type ThreatPattern struct {
	Name  string
	Re    *regexp.Regexp
	Hints []string
}

type UAClass struct {
	Name string
	Re   *regexp.Regexp
}

type KV struct {
	Key string
	Val int
}

type KVInt struct {
	Key int
	Val int
}

type KV64 struct {
	Key string
	Val int64
}

// Config type alias
type Cfg = map[string]interface{}

// Command context passed to dispatch
type CmdCtx struct {
	Data      *ParseData
	Cfg       Cfg
	Geo       map[string]string
	GeoFull   map[string][2]string
	WLRaw     []string
	WLNets    []net.IPNet
	FilterIP  string
	OutputIPs bool
}
