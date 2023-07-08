package controller

import (
	"encoding/json"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/xcode75/xcore/infra/conf"
	"github.com/xcode75/xcore/common/net"
	"github.com/xcode75/xcore/common/protocol"
	"github.com/xcode75/xcore/common/serial"
	"github.com/xcode75/xcore/proxy/trojan"
	"github.com/xcode75/xcore/common/uuid"
	"github.com/xcode75/xcore/proxy/vless"
	vlessoutbound "github.com/xcode75/xcore/proxy/vless/outbound"
	"github.com/xcode75/xcore/proxy/vmess"
	"github.com/xcode75/xcore/proxy/vmess/outbound"
	"github.com/xcode75/xcore/proxy/shadowsocks"
	"github.com/xcode75/xcore/proxy/shadowsocks_2022"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	core "github.com/xcode75/xcore/core"
	"github.com/xcode75/xcore/app/proxyman"
	"github.com/xcode75/xcore/transport/internet"
)

type Address struct {
	net.Address
}

func (v *Address) UnmarshalJSON(data []byte) error {
	var rawStr string
	if err := json.Unmarshal(data, &rawStr); err != nil {
		return newError("invalid address: ", string(data)).Base(err)
	}
	v.Address = net.ParseAddress(rawStr)

	return nil
}

func (v *Address) Build() *net.IPOrDomain {
	return net.NewIPOrDomain(v.Address)
}

// TrojanServerTarget is configuration of a single trojan server
type TrojanServerTarget struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Password string   `json:"password"`
	Email    string   `json:"email"`
	Level    byte     `json:"level"`
	Flow     string   `json:"flow"`
}

// TrojanClientConfig is configuration of trojan servers
type TrojanClientConfig struct {
	Servers []*TrojanServerTarget `json:"servers"`
}

// Build implements Buildable
func (c *TrojanClientConfig) Build() (proto.Message, error) {
	if len(c.Servers) == 0 {
		return nil, newError("0 Trojan server configured.")
	}

	config := &trojan.ClientConfig{
		Server: make([]*protocol.ServerEndpoint, len(c.Servers)),
	}

	for idx, rec := range c.Servers {
		if rec.Address == nil {
			return nil, newError("Trojan server address is not set.")
		}
		if rec.Port == 0 {
			return nil, newError("Invalid Trojan port.")
		}
		if rec.Password == "" {
			return nil, newError("Trojan password is not specified.")
		}
		if rec.Flow != "" {
			return nil, newError(`Trojan doesn't support "flow" anymore.`)
		}

		config.Server[idx] = &protocol.ServerEndpoint{
			Address: rec.Address.Build(),
			Port:    uint32(rec.Port),
			User: []*protocol.User{
				{
					Level: uint32(rec.Level),
					Email: rec.Email,
					Account: serial.ToTypedMessage(&trojan.Account{
						Password: rec.Password,
					}),
				},
			},
		}
	}

	return config, nil
}

type VLessOutboundVnext struct {
	Address *Address          `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type VLessOutboundConfig struct {
	Vnext []*VLessOutboundVnext `json:"vnext"`
}

// Build implements Buildable
func (c *VLessOutboundConfig) Build() (proto.Message, error) {
	config := new(vlessoutbound.Config)

	if len(c.Vnext) == 0 {
		return nil, newError(`VLESS settings: "vnext" is empty`)
	}
	config.Vnext = make([]*protocol.ServerEndpoint, len(c.Vnext))
	for idx, rec := range c.Vnext {
		if rec.Address == nil {
			return nil, newError(`VLESS vnext: "address" is not set`)
		}
		if len(rec.Users) == 0 {
			return nil, newError(`VLESS vnext: "users" is empty`)
		}
		spec := &protocol.ServerEndpoint{
			Address: rec.Address.Build(),
			Port:    uint32(rec.Port),
			User:    make([]*protocol.User, len(rec.Users)),
		}
		for idx, rawUser := range rec.Users {
			user := new(protocol.User)
			if err := json.Unmarshal(rawUser, user); err != nil {
				return nil, newError(`VLESS users: invalid user`).Base(err)
			}
			account := new(vless.Account)
			if err := json.Unmarshal(rawUser, account); err != nil {
				return nil, newError(`VLESS users: invalid user`).Base(err)
			}
			
			accid := strings.Split(user.Email, "|")
			u, err := uuid.ParseString(accid[2])
			//u, err := uuid.ParseString(account.Id)
			if err != nil {
				return nil, err
			}
			account.Id = u.String()

			switch account.Flow {
			case "", vless.XRV, vless.XRV + "-udp443":
			default:
				return nil, newError(`VLESS users: "flow" doesn't support "` + account.Flow + `" in this version`)
			}

			if account.Encryption != "none" {
				account.Encryption = "none"
			}

			user.Account = serial.ToTypedMessage(account)
			spec.User[idx] = user
		}
		config.Vnext[idx] = spec
	}

	return config, nil
}


type VMessAccount struct {
	ID          string `json:"id"`
	AlterIds    uint16 `json:"alterId"`
	Security    string `json:"security"`
	Experiments string `json:"experiments"`
}

// Build implements Buildable
func (a *VMessAccount) Build() *vmess.Account {
	var st protocol.SecurityType
	switch strings.ToLower(a.Security) {
	case "aes-128-gcm":
		st = protocol.SecurityType_AES128_GCM
	case "chacha20-poly1305":
		st = protocol.SecurityType_CHACHA20_POLY1305
	case "auto":
		st = protocol.SecurityType_AUTO
	case "none":
		st = protocol.SecurityType_NONE
	case "zero":
		st = protocol.SecurityType_ZERO
	default:
		st = protocol.SecurityType_AUTO
	}
	return &vmess.Account{
		Id:      a.ID,
		SecuritySettings: &protocol.SecurityConfig{
			Type: st,
		},
		TestsEnabled: a.Experiments,
	}
}

type VMessOutboundTarget struct {
	Address *Address          `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type VMessOutboundConfig struct {
	Receivers []*VMessOutboundTarget `json:"vnext"`
}

// Build implements Buildable
func (c *VMessOutboundConfig) Build() (proto.Message, error) {
	config := new(outbound.Config)

	if len(c.Receivers) == 0 {
		return nil, newError("0 VMess receiver configured")
	}
	serverSpecs := make([]*protocol.ServerEndpoint, len(c.Receivers))
	for idx, rec := range c.Receivers {
		if len(rec.Users) == 0 {
			return nil, newError("0 user configured for VMess outbound")
		}
		if rec.Address == nil {
			return nil, newError("address is not set in VMess outbound config")
		}
		spec := &protocol.ServerEndpoint{
			Address: rec.Address.Build(),
			Port:    uint32(rec.Port),
		}
		for _, rawUser := range rec.Users {
			user := new(protocol.User)
			if err := json.Unmarshal(rawUser, user); err != nil {
				return nil, newError("invalid VMess user").Base(err)
			}
			account := new(VMessAccount)
			if err := json.Unmarshal(rawUser, account); err != nil {
				return nil, newError("invalid VMess user").Base(err)
			}

			accid := strings.Split(user.Email, "|")
			u, err := uuid.ParseString(accid[2])
			//u, err := uuid.ParseString(account.ID)
			if err != nil {
				return nil, err
			}
			account.ID = u.String()

			user.Account = serial.ToTypedMessage(account.Build())
			spec.User = append(spec.User, user)
		}
		serverSpecs[idx] = spec
	}
	config.Receiver = serverSpecs
	return config, nil
}

func cipherFromString(c string) shadowsocks.CipherType {
	switch strings.ToLower(c) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305
	case "none", "plain":
		return shadowsocks.CipherType_NONE
	default:
		return shadowsocks.CipherType_UNKNOWN
	}
}


type ShadowsocksServerTarget struct {
	Address    *Address `json:"address"`
	Port       uint16   `json:"port"`
	Cipher     string   `json:"method"`
	Password   string   `json:"password"`
	Email      string   `json:"email"`
	Level      byte     `json:"level"`
	IVCheck    bool     `json:"ivCheck"`
	UoT        bool     `json:"uot"`
	UoTVersion int      `json:"uotVersion"`
}

type ShadowsocksClientConfig struct {
	Servers []*ShadowsocksServerTarget `json:"servers"`
}

func (v *ShadowsocksClientConfig) Build() (proto.Message, error) {
	if len(v.Servers) == 0 {
		return nil, newError("0 Shadowsocks server configured.")
	}

	if len(v.Servers) == 1 {
		server := v.Servers[0]
		if C.Contains(shadowaead_2022.List, server.Cipher) {
			if server.Address == nil {
				return nil, newError("Shadowsocks server address is not set.")
			}
			if server.Port == 0 {
				return nil, newError("Invalid Shadowsocks port.")
			}
			if server.Password == "" {
				return nil, newError("Shadowsocks password is not specified.")
			}

			config := new(shadowsocks_2022.ClientConfig)
			config.Address = server.Address.Build()
			config.Port = uint32(server.Port)
			config.Method = server.Cipher
			config.Key = server.Password
			config.UdpOverTcp = server.UoT
			config.UdpOverTcpVersion = uint32(server.UoTVersion)
			return config, nil
		}
	}

	config := new(shadowsocks.ClientConfig)
	serverSpecs := make([]*protocol.ServerEndpoint, len(v.Servers))
	for idx, server := range v.Servers {
		if C.Contains(shadowaead_2022.List, server.Cipher) {
			return nil, newError("Shadowsocks 2022 accept no multi servers")
		}
		if server.Address == nil {
			return nil, newError("Shadowsocks server address is not set.")
		}
		if server.Port == 0 {
			return nil, newError("Invalid Shadowsocks port.")
		}
		if server.Password == "" {
			return nil, newError("Shadowsocks password is not specified.")
		}
		account := &shadowsocks.Account{
			Password: server.Password,
		}
		account.CipherType = cipherFromString(server.Cipher)
		if account.CipherType == shadowsocks.CipherType_UNKNOWN {
			return nil, newError("unknown cipher method: ", server.Cipher)
		}

		account.IvCheck = server.IVCheck

		ss := &protocol.ServerEndpoint{
			Address: server.Address.Build(),
			Port:    uint32(server.Port),
			User: []*protocol.User{
				{
					Level:   uint32(server.Level),
					Email:   server.Email,
					Account: serial.ToTypedMessage(account),
				},
			},
		}

		serverSpecs[idx] = ss
	}

	config.Server = serverSpecs

	return config, nil
}

var (
	outboundConfigLoader = conf.NewJSONConfigLoader(conf.ConfigCreatorCache{
		"shadowsocks": func() interface{} { return new(ShadowsocksClientConfig) },
		"vless":       func() interface{} { return new(VLessOutboundConfig) },
		"vmess":       func() interface{} { return new(VMessOutboundConfig) },
		"trojan":      func() interface{} { return new(TrojanClientConfig) },
	}, "protocol", "settings")
)

type OutboundDetourConfig struct {
	Protocol      string                `json:"protocol"`
	SendThrough   *conf.Address         `json:"sendThrough"`
	Tag           string                `json:"tag"`
	Settings      *json.RawMessage      `json:"settings"`
	StreamSetting *conf.StreamConfig    `json:"streamSettings"`
	ProxySettings *conf.ProxyConfig     `json:"proxySettings"`
	MuxSettings   *conf.MuxConfig       `json:"mux"`
}

func (c *OutboundDetourConfig) checkChainProxyConfig() error {
	if c.StreamSetting == nil || c.ProxySettings == nil || c.StreamSetting.SocketSettings == nil {
		return nil
	}
	if len(c.ProxySettings.Tag) > 0 && len(c.StreamSetting.SocketSettings.DialerProxy) > 0 {
		return newError("proxySettings.tag is conflicted with sockopt.dialerProxy").AtWarning()
	}
	return nil
}

// Build implements Buildable.
func (c *OutboundDetourConfig) Build() (*core.OutboundHandlerConfig, error) {
	senderSettings := &proxyman.SenderConfig{}
	if err := c.checkChainProxyConfig(); err != nil {
		return nil, err
	}

	if c.SendThrough != nil {
		address := c.SendThrough
		if address.Family().IsDomain() {
			return nil, newError("unable to send through: " + address.String())
		}
		senderSettings.Via = address.Build()
	}

	if c.StreamSetting != nil {
		ss, err := c.StreamSetting.Build()
		if err != nil {
			return nil, err
		}
		senderSettings.StreamSettings = ss
	}

	if c.ProxySettings != nil {
		ps, err := c.ProxySettings.Build()
		if err != nil {
			return nil, newError("invalid outbound detour proxy settings.").Base(err)
		}
		if ps.TransportLayerProxy {
			if senderSettings.StreamSettings != nil {
				if senderSettings.StreamSettings.SocketSettings != nil {
					senderSettings.StreamSettings.SocketSettings.DialerProxy = ps.Tag
				} else {
					senderSettings.StreamSettings.SocketSettings = &internet.SocketConfig{DialerProxy: ps.Tag}
				}
			} else {
				senderSettings.StreamSettings = &internet.StreamConfig{SocketSettings: &internet.SocketConfig{DialerProxy: ps.Tag}}
			}
			ps = nil
		}
		senderSettings.ProxySettings = ps
	}

	if c.MuxSettings != nil {
		ms, err := c.MuxSettings.Build()
		if err != nil {
			return nil, newError("failed to build Mux config.").Base(err)
		}
		senderSettings.MultiplexSettings = ms
	}

	settings := []byte("{}")
	if c.Settings != nil {
		settings = ([]byte)(*c.Settings)
	}
	rawConfig, err := outboundConfigLoader.LoadWithID(settings, c.Protocol)
	if err != nil {
		return nil, newError("failed to parse to outbound detour config.").Base(err)
	}
	ts, err := rawConfig.(conf.Buildable).Build()
	if err != nil {
		return nil, err
	}

	return &core.OutboundHandlerConfig{
		SenderSettings: serial.ToTypedMessage(senderSettings),
		Tag:            c.Tag,
		ProxySettings:  serial.ToTypedMessage(ts),
	}, nil
}