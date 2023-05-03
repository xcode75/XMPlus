package xmplus

import "encoding/json"

type serverConfig struct {
	server  `json:"server"`
	Relay   bool 	 `json:"relay"`
	relay_server     `json:"relay_server"`
	Routes []route   `json:"routes"`
	Fallback bool 	`json:"fallback"`
	Fallbacks []fallbackconf `json:"fallbacks"`
}

type server struct {
	Address     string 	 `json:"address"`
	Certmode    string 	 `json:"certmode"`
	Cipher      string 	 `json:"cipher"`
	Domainstrategy string `json:"domainstrategy"`
	EnableDns   bool 	 `json:"enable_dns"`
	IP          string   `json:"ip"`
	Port        int      `json:"listeningport"`
	Listenip    string   `json:"listenip"`
	Network     string   `json:"network"`
	NetworkSettings struct {
	    ProxyProtocol bool 	         `json:"acceptProxyProtocol"`
		Path        string           `json:"path"`
		Host        string           `json:"host"`
		QuicSecurity string          `json:"security"`
		Quickey      string          `json:"key"`
		Headers     *json.RawMessage `json:"headers"`
		ServiceName string           `json:"serviceName"`
		Header      *json.RawMessage `json:"header"`
		Transport   string           `json:"transport"`
		Seed        string           `json:"seed"`
		Congestion  bool 	         `json:"congestion"`
	} `json:"networkSettings"`
	Security string `json:"security"`
	SecuritySettings struct {
	    AllowInsecure bool 	   `json:"allowInsecure"`
		Fingerprint   string   `json:"fingerprint"`
		RejectUnknownSni  bool `json:"rejectUnknownSni"`
		ServerName   string    `json:"serverName"`
		Flow         string    `json:"flow"`
		Alpn         string    `json:"alpn"`
		PrivateKey   string    `json:"privatekey"`
		ShortIds     string    `json:"shortids"`
		Show         bool      `json:"show"`
		Dest         string    `json:"dest"`
		Xver         int       `json:"xver"`
		MaxTimeDiff  int 	   `json:"maxtimediff"`
		MinClientVer string    `json:"minclientver"`
		MaxClientVer string    `json:"minclientver"`
	} `json:"securitySettings"`	
	Relayid   int       `json:"relayid"`
	SendThrough string  `json:"sendthrough"`
	ServerKey  string   `json:"server_key"`
	Sniffing  bool 	    `json:"sniffing"`
	Speedlimit  int     `json:"speedlimit"`
	Type    string      `json:"type"`
}

type relay_server struct {
	RId          int        `json:"id"`
	RAddress     string 	`json:"address"`
	RServerid    int 	    `json:"serverid"`
	RCipher      string 	`json:"cipher"`
	RDomainstrategy string  `json:"domainstrategy"`
	REnableDns   bool 	    `json:"enable_dns"`
	RIP          string     `json:"ip"`
	RPort        int        `json:"listeningport"`
	RListenip    string     `json:"listenip"`
	RNetwork     string     `json:"network"`
	RNetworkSettings struct {
	    ProxyProtocol bool 	         `json:"acceptProxyProtocol"`
		Path        string           `json:"path"`
		Host        string           `json:"host"`
		QuicSecurity string          `json:"security"`
		Quickey      string          `json:"key"`
		Headers     *json.RawMessage `json:"headers"`
		ServiceName string           `json:"serviceName"`
		Header      *json.RawMessage `json:"header"`
		Transport   string           `json:"transport"`
		Seed        string           `json:"seed"`
		Congestion  bool 	         `json:"congestion"`
	} `json:"networkSettings"`
	RSecurity string `json:"security"`
	RSecuritySettings struct {
	    AllowInsecure bool 	   `json:"allowInsecure"`
		Fingerprint   string   `json:"fingerprint"`
		RejectUnknownSni  bool `json:"rejectUnknownSni"`
		ServerName   string    `json:"serverName"`
		Flow         string    `json:"flow"`
		Alpn         string    `json:"alpn"`
		PublicKey    string    `json:"publickey"`
		ShortId      string    `json:"shortid"`
		SpiderX      string    `json:"spiderx"`
		Show         bool      `json:"show"`
	} `json:"securitySettings"`	
	RSendThrough string   `json:"sendthrough"`
	RServerKey  string    `json:"server_key"`
	RSniffing  bool 	  `json:"sniffing"`
	RSpeedlimit  int      `json:"speedlimit"`
	RType     string      `json:"type"`
}

type route struct {
	Id       int      `json:"id"`
	Regex    string   `json:"regex"`
}

type fallbackconf struct {
	Id         int      `json:"id"`
	Alpn       string   `json:"alpn"`
	Dest       string   `json:"dest"`
	Path       string   `json:"path"`
	SNI        string   `json:"sni"`
	ProxyProtocol int 	`json:"proxyprotocolver"`
}