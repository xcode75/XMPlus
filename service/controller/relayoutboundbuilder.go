package controller

import (
	"encoding/json"
	"fmt"
	
	"github.com/xcode75/XMPlus/api"
	"github.com/xcode75/xcore/common/net"
	"github.com/xcode75/xcore/core"
	"github.com/xcode75/xcore/infra/conf"
	"github.com/xcode75/xcore/common/protocol"
	"github.com/xcode75/xcore/common/serial"
	"github.com/xcode75/xcore/proxy/vless"
)

type VMessOutbound struct {
	Address string            `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type VLessOutbound struct {
	Address string            `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type TrojanServer struct {
	Address  string        `json:"address"`
	Port     uint16        `json:"port"`
	Password string        `json:"password"`
	Email    string        `json:"email"`
	Level    byte          `json:"level"`
	Flow     string        `json:"flow"`
}

type ShadowsocksServer struct {
	Address  string          `json:"address"`
	Port     uint16          `json:"port"`
	Cipher   string          `json:"method"`
	Password string          `json:"password"`
	Email    string          `json:"email"`
	Level    byte            `json:"level"`
	UoT      bool            `json:"uot"`
}

func OutboundRelayBuilder(config *Config, nodeInfo *api.RelayNodeInfo , tag string, UUID string, Email string, Passwd string, UID int) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &OutboundDetourConfig{}
	var (
		protocol      string
		streamSetting *conf.StreamConfig
		setting       json.RawMessage
	)

	var proxySetting any
	
	switch nodeInfo.NodeType {
		case "Vless":
			protocol = "vless"
			VlessUser := buildRVlessUser(tag, nodeInfo.Flow , UUID, Email)
			User := []json.RawMessage{}
			rawUser,err := json.Marshal(&VlessUser)
			if err != nil {
				return nil, fmt.Errorf("Marshal users %s config fialed: %s", VlessUser, err)
			}
			
			User = append(User, rawUser)
			proxySetting = struct {
				Vnext []*VLessOutbound `json:"vnext"`
			}{
				Vnext: []*VLessOutbound{&VLessOutbound{
						Address: nodeInfo.Address,
						Port: uint16(nodeInfo.Port),
						Users: User,
					},
				},
			}
		case "Vmess":
			protocol = "vmess"
			VmessUser := buildRVmessUser(tag, UUID, Email)
			User := []json.RawMessage{}
			rawUser,err := json.Marshal(&VmessUser)
			if err != nil {
				return nil, fmt.Errorf("Marshal users %s config fialed: %s", VmessUser, err)
			}
			
			User = append(User, rawUser)					
			proxySetting = struct {
				Receivers []*VMessOutbound `json:"vnext"`
			}{
				Receivers: []*VMessOutbound{&VMessOutbound{
						Address: nodeInfo.Address,
						Port: uint16(nodeInfo.Port),
						Users: User,
					},
				},
			}
		case "Trojan":
			protocol = "trojan"	
			proxySetting = struct {
				Servers []*TrojanServer `json:"servers"`
			}{
				Servers: []*TrojanServer{&TrojanServer{
						Address: nodeInfo.Address,
						Port:     uint16(nodeInfo.Port),
						Password: UUID,
						Email:    fmt.Sprintf("%s|%s|%s", tag, Email, UUID),
						Level:    0,
					},
				},
			}
		case "Shadowsocks":
			protocol = "shadowsocks"
			proxySetting = struct {
				Servers []*ShadowsocksServer `json:"servers"`
			}{
				Servers: []*ShadowsocksServer{&ShadowsocksServer{
						Address: nodeInfo.Address,
						Port:     uint16(nodeInfo.Port),
						Password: Passwd,
						Email:    fmt.Sprintf("%s|%s|%s", tag, Email, UID),
						Level:    0,
						Cipher:   nodeInfo.CypherMethod,
						UoT:      true,
					},
				},
			}
		default:
			return nil, fmt.Errorf("Unsupported Relay Node Type: %s", nodeInfo.NodeType)	
	}  
	
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config fialed: %s", nodeInfo.NodeType, err)
	}
	
	outboundDetourConfig.Protocol = protocol
	
	outboundDetourConfig.Settings = &setting
	
	streamSetting = new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol(nodeInfo.TransportProtocol)
	networkType, err := transportProtocol.Build()
	if err != nil {
		return nil, fmt.Errorf("convert TransportProtocol failed: %s", err)
	}

	switch networkType {
	case "tcp":
		tcpSetting := &conf.TCPConfig{
			AcceptProxyProtocol: nodeInfo.ProxyProtocol,
			HeaderConfig:        nodeInfo.Header,
		}
		streamSetting.TCPSettings = tcpSetting
	case "websocket":
		headers := make(map[string]string)
		headers["Host"] = nodeInfo.Host
		wsSettings := &conf.WebSocketConfig{
			AcceptProxyProtocol: nodeInfo.ProxyProtocol,
			Path:                nodeInfo.Path,
			Headers:             headers,
		}
		streamSetting.WSSettings = wsSettings
	case "http":
		hosts := conf.StringList{nodeInfo.Host}
		httpSettings := &conf.HTTPConfig{
			Host: &hosts,
			Path: nodeInfo.Path,
		}
		streamSetting.HTTPSettings = httpSettings
	case "grpc":
		grpcSettings := &conf.GRPCConfig{
			ServiceName: nodeInfo.ServiceName,
		}
		streamSetting.GRPCConfig = grpcSettings
	case "quic":
		quicSettings := &conf.QUICConfig{
			Security:  nodeInfo.Quic_security,
			Header:    nodeInfo.Header,
			Key:       nodeInfo.Quic_key,
		}
		streamSetting.QUICSettings = quicSettings
	case "mkcp":
		kcpSettings := &conf.KCPConfig{
			HeaderConfig:    nodeInfo.Header,
			Congestion:      &nodeInfo.Congestion,
			Seed:            &nodeInfo.Seed,
		}
		streamSetting.KCPSettings = kcpSettings	
	}
	
	streamSetting.Network = &transportProtocol
	
	if nodeInfo.TLSType == "tls" {
		streamSetting.Security = "tls"
		if nodeInfo.TLSType == "tls" {
			tlsSettings := &conf.TLSConfig{}
			tlsSettings.Insecure = true
			if nodeInfo.Alpn != "" {
				alpn := conf.StringList{nodeInfo.Alpn}
				tlsSettings.ALPN = &alpn
			}
			tlsSettings.Fingerprint = nodeInfo.Fingerprint
			streamSetting.TLSSettings = tlsSettings	
		}
	}
	
	if nodeInfo.TLSType == "reality" {
		streamSetting.Security = "reality"
		
		realitySettings :=  &conf.REALITYConfig{
			Show:         nodeInfo.Show,
			ServerName:   nodeInfo.ServerName,
			PublicKey:    nodeInfo.PublicKey,
			Fingerprint:  nodeInfo.Fingerprint,
			ShortId:      nodeInfo.ShortId,
			SpiderX:      nodeInfo.SpiderX,
		}
		streamSetting.REALITYSettings = realitySettings
	}
	
	outboundDetourConfig.Tag = fmt.Sprintf("%s_%d", tag,UID)
	
	if nodeInfo.SendIP != "" {
		ipAddress := net.ParseAddress(nodeInfo.SendIP)
		outboundDetourConfig.SendThrough = &conf.Address{Address: ipAddress}
	}
	outboundDetourConfig.StreamSetting = streamSetting
	
	return outboundDetourConfig.Build()
}

func buildRVmessUser(tag string, UUID string, Email string) *protocol.User {
	vmessAccount := &VMessAccount{
		ID:       UUID,
		Security: "auto",
	}
	return &protocol.User{
		Level:   0,
		Email:   fmt.Sprintf("%s|%s|%s", tag, Email, UUID), 
		Account: serial.ToTypedMessage(vmessAccount.Build()),
	}
}

func buildRVlessUser(tag string, Flow string, UUID string, Email string)  *protocol.User {
	vlessAccount := &vless.Account{
		Id:   UUID,
		Flow: Flow,
		Encryption: "none",
	}
	return &protocol.User{
		Level:   0,
		Email:   fmt.Sprintf("%s|%s|%s", tag, Email, UUID),
		Account: serial.ToTypedMessage(vlessAccount),
	}
}
