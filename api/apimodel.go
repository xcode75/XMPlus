package api

import (
	"regexp"
)

// API config
type Config struct {
	APIHost      string  `mapstructure:"ApiHost"`
	NodeID       int     `mapstructure:"NodeID"`
	Key          string  `mapstructure:"ApiKey"`
	Timeout      int     `mapstructure:"Timeout"`
	SpeedLimit   float64 `mapstructure:"SpeedLimit"`
	DeviceLimit  int     `mapstructure:"DeviceLimit"`
	RuleListPath string  `mapstructure:"RuleListPath"`
}

// Node status
type NodeStatus struct {
	CPU    float64
	Mem    float64
	Disk   float64
	Uptime uint64
}

type NodeInfo struct {
	NodeType          string 
	NodeID            int
	Port              uint32
	SpeedLimit        uint64 // Bps
	AlterID           uint16
	TransportProtocol string
	Host              string
	Path              string
	EnableTLS         bool
	TLSType           string
	CypherMethod      string
	ServiceName       string
	HeaderType        string
	AllowInsecure     bool
	RelayNodeID		  int
	ListenIP          string
	ProxyProtocol     bool
	Sniffing          bool
	Address           string
	Fingerprint       string
	RejectUnknownSNI  bool   
	Quic_security     string    
	Quic_key          string  
}

type TransitNodeInfo struct {
	NodeType          string 
	NodeID            int
	Port              uint32
	SpeedLimit        uint64 // Bps
	AlterID           uint16
	TransportProtocol string
	Host              string
	Path              string
	EnableTLS         bool
	TLSType           string
	CypherMethod      string
	ServiceName       string
	HeaderType        string
	AllowInsecure     bool
	Address           string
	ListenIP          string
	ProxyProtocol     bool
	Sniffing          bool
	Flow              string
	Fingerprint       string
	RejectUnknownSNI  bool   
	Quic_security     string    
	Quic_key          string  
}

type UserInfo struct {
	UID           int
	Email         string
	Passwd        string
	Port          int
	SpeedLimit    uint64 
	DeviceLimit   int
	UUID          string
}

type OnlineUser struct {
	UID int
	IP  string
}

type UserTraffic struct {
	UID      int
	Email    string
	Upload   int64
	Download int64
}

type ClientInfo struct {
	APIHost  string
	NodeID   int
	Key      string
}

type DetectRule struct {
	ID      int
	Pattern *regexp.Regexp
}

type DetectResult struct {
	UID    int
	RuleID int
}
