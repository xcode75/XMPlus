package controller

import (
	"encoding/json"
	"fmt"

	"github.com/xcode75/XMPlus/api"
	"github.com/xcode75/XMCore/common/net"
	"github.com/xcode75/XMCore/core"
	"github.com/xcode75/XMCore/infra/conf"
	
	"github.com/xcode75/XMCore/common/protocol"
	"github.com/xcode75/XMCore/common/serial"
	"github.com/xcode75/XMCore/proxy/vless"
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
	IVCheck  bool            `json:"ivCheck"`
}


func TransitBuilder(config *Config, nodeInfo *api.TransitNodeInfo , tag string, UUID string, Email string, Passwd string, UID int) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &OutboundDetourConfig{}
	var (
		protocol      string
		streamSetting *conf.StreamConfig
		setting       json.RawMessage
	)

	var proxySetting interface{}

	if nodeInfo.NodeType == "Vless" {
		protocol = "vless"
		VlessUser := buildRVlessUser(tag, nodeInfo , UUID, Email)
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
	}else if nodeInfo.NodeType == "Vmess" {
		protocol = "vmess"
		VmessUser := buildRVmessUser(tag, UUID, Email, nodeInfo.AlterID)
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
	}else if nodeInfo.NodeType == "Trojan" {
		protocol = "trojan"	
		if nodeInfo.TLSType == "xtls" {
			proxySetting = struct {
				Servers []*TrojanServer `json:"servers"`
			}{
				Servers: []*TrojanServer{&TrojanServer{
						Address:  nodeInfo.Address,
						Port:     uint16(nodeInfo.Port),
						Password: UUID,
						Email:    fmt.Sprintf("%s_%s|%s", tag, Email, UUID),
						Level:    0,
						Flow:    nodeInfo.Flow,
					},
				},
			}
		} else {
			proxySetting = struct {
				Servers []*TrojanServer `json:"servers"`
			}{
				Servers: []*TrojanServer{&TrojanServer{
						Address: nodeInfo.Address,
						Port:     uint16(nodeInfo.Port),
						Password: UUID,
						Email:    fmt.Sprintf("%s_%s|%s", tag, Email, UUID),
						Level:    0,
					},
				},
			}
		}
	}else if nodeInfo.NodeType == "Shadowsocks" {
		protocol = "shadowsocks"	
		proxySetting = struct {
			Servers []*ShadowsocksServer `json:"servers"`
		}{
			Servers: []*ShadowsocksServer{&ShadowsocksServer{
					Address: nodeInfo.Address,
					Port:     uint16(nodeInfo.Port),
					Password: Passwd,
					Email:    fmt.Sprintf("%s_%s|%s", tag, Email, UUID),
					Level:    0,
					Cipher:   nodeInfo.CypherMethod,
				},
			},
		}
	}else{
		return nil, fmt.Errorf("Unsupported node type: %s", nodeInfo.NodeType)
	}
		
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("Marshal proxy %s config fialed: %s", nodeInfo.NodeType, err)
	}
		
	streamSetting = new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol(nodeInfo.TransportProtocol)
	networkType, err := transportProtocol.Build()
	if err != nil {
		return nil, fmt.Errorf("convert TransportProtocol failed: %s", err)
	}
		
	if networkType == "tcp" {
		headers := make(map[string]string)
		headers["type"] = nodeInfo.HeaderType
		var header json.RawMessage
		header, err  := json.Marshal(headers)
		if err != nil {
			return nil, fmt.Errorf("Marshal Header Type %s into config fialed: %s", header, err)
		}		
		tcpSetting := &conf.TCPConfig{
			AcceptProxyProtocol: nodeInfo.ProxyProtocol,
			HeaderConfig:        header,
		}
		streamSetting.TCPSettings = tcpSetting
	} else if networkType == "websocket" {
		headers := make(map[string]string)
		headers["Host"] = nodeInfo.Host
		wsSettings := &conf.WebSocketConfig{
			AcceptProxyProtocol: nodeInfo.ProxyProtocol,
			Path:      nodeInfo.Path,
			Headers:   headers,
		}
		streamSetting.WSSettings = wsSettings
	} else if networkType == "http" {
		hosts := conf.StringList{nodeInfo.Host}
		httpSettings := &conf.HTTPConfig{
			Host: &hosts,
			Path: nodeInfo.Path,
		}
		streamSetting.HTTPSettings = httpSettings
	}else if networkType == "grpc" {
		grpcSettings := &conf.GRPCConfig{
			ServiceName: nodeInfo.ServiceName,
		}
		streamSetting.GRPCConfig = grpcSettings
	} else if networkType == "quic" {
		headers := make(map[string]string)
		headers["type"] = nodeInfo.HeaderType
		var header json.RawMessage
		header, err := json.Marshal(headers)
		if err != nil {
			return nil, fmt.Errorf("Marshal Header Type %s into config fialed: %s", header, err)
		}
		quicSettings := &conf.QUICConfig{
			Security:  nodeInfo.Quic_security,
			Header:    header,
			Key:       nodeInfo.Quic_key,
		}
		streamSetting.QUICSettings = quicSettings
	}
		
	streamSetting.Network = &transportProtocol
		
	if nodeInfo.EnableTLS{
		streamSetting.Security = nodeInfo.TLSType
		if nodeInfo.TLSType == "tls" {
			tlsSettings := &conf.TLSConfig{}
			tlsSettings.Insecure = true
			tlsSettings.Fingerprint = nodeInfo.Fingerprint
			streamSetting.TLSSettings = tlsSettings	
		} else if nodeInfo.TLSType == "xtls" {
			xtlsSettings := &conf.XTLSConfig{}
			xtlsSettings.Insecure = true
			streamSetting.XTLSSettings = xtlsSettings
		}
	}
	
	outboundDetourConfig.Tag = fmt.Sprintf("Relay_%s|%d", tag,UID)
	
	if config.SendIP != "" {
		ipAddress := net.ParseAddress(config.SendIP)
		outboundDetourConfig.SendThrough = &conf.Address{ipAddress}
	}
	outboundDetourConfig.Protocol = protocol
	outboundDetourConfig.StreamSetting = streamSetting
	outboundDetourConfig.Settings = &setting
	
	return outboundDetourConfig.Build()
}


func buildRVmessUser(tag string, UUID string, Email string, serverAlterID uint16) *protocol.User {
	vmessAccount := &VMessAccount{
		ID:       UUID,
		AlterIds: uint16(serverAlterID),
		Security: "auto",
	}
	return &protocol.User{
		Level:   0,
		Email:   fmt.Sprintf("%s_%s|%s", tag,Email, UUID), 
		Account: serial.ToTypedMessage(vmessAccount.Build()),
	}
}

func buildRVlessUser(tag string, nodeInfo *api.TransitNodeInfo , UUID string, Email string)  *protocol.User {
	var xtlsFlow string
	if nodeInfo.TLSType == "xtls" {
		xtlsFlow = nodeInfo.Flow
	}
	vlessAccount := &vless.Account{
		Id:   UUID,
		Flow: xtlsFlow,
		Encryption: "none",
	}
	return &protocol.User{
		Level:   0,
		Email:   fmt.Sprintf("%s_%s|%s", tag, Email, UUID),
		Account: serial.ToTypedMessage(vlessAccount),
	}
}

