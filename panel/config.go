package panel

import (
	"github.com/xcode75/XMPlus/api"
	"github.com/xcode75/XMPlus/service/controller"
)

type Config struct {
	LogConfig          *LogConfig       `mapstructure:"Log"`
	DnsConfigPath      string           `mapstructure:"DnsConfigPath"`
	ConnetionConfig    *ConnetionConfig `mapstructure:"ConnetionConfig"`
	OutboundConfigPath string           `mapstructure:"OutboundConfigPath"`
	RouteConfigPath    string           `mapstructure:"RouteConfigPath"`
	NodesConfig        []*NodesConfig   `mapstructure:"Nodes"`
}

type NodesConfig struct {
	ApiConfig        *api.Config        `mapstructure:"ApiConfig"`
	ControllerConfig *controller.Config `mapstructure:"ControllerConfig"`
}

type LogConfig struct {
	Level      string `mapstructure:"Level"`
	AccessPath string `mapstructure:"AccessPath"`
	ErrorPath  string `mapstructure:"ErrorPath"`
}

type ConnetionConfig struct {
	Handshake    uint32 `mapstructure:"handshake"`
	ConnIdle     uint32 `mapstructure:"connIdle"`
	UplinkOnly   uint32 `mapstructure:"uplinkOnly"`
	DownlinkOnly uint32 `mapstructure:"downlinkOnly"`
	BufferSize   int32  `mapstructure:"bufferSize"`
}