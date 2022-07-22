package controller

type Config struct {
	SendIP              string            `mapstructure:"SendIP"`
	UpdatePeriodic      int               `mapstructure:"UpdatePeriodic"`
	CertConfig          *CertConfig       `mapstructure:"CertConfig"`
	EnableDNS           bool              `mapstructure:"EnableDNS"`
	DNSType             string            `mapstructure:"DNSType"`
	DisableUploadTraffic bool             `mapstructure:"DisableUploadTraffic"`
	DisableGetRule      bool              `mapstructure:"DisableGetRule"`
	EnableFallback      bool              `mapstructure:"EnableFallback"`
	DisableIVCheck      bool              `mapstructure:"DisableIVCheck"`
	FallBackConfigs     []*FallBackConfig `mapstructure:"FallBackConfigs"`
}

type CertConfig struct {
	CertMode   string            `mapstructure:"CertMode"` // none, file, http, dns
	CertDomain string            `mapstructure:"CertDomain"`
	CertFile   string            `mapstructure:"CertFile"`
	KeyFile    string            `mapstructure:"KeyFile"`
	Provider   string            `mapstructure:"Provider"` // alidns, cloudflare, gandi, godaddy....
	Email      string            `mapstructure:"Email"`
	DNSEnv     map[string]string `mapstructure:"DNSEnv"`
}

type FallBackConfig struct {
	SNI              string `mapstructure:"SNI"`
	Path             string `mapstructure:"Path"`
	Dest             string `mapstructure:"Dest"`
	ProxyProtocolVer uint64    `mapstructure:"ProxyProtocolVer"`
}
