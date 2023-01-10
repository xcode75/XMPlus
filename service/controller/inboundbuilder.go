// Package controller Package generate the InboundConfig used by add inbound
package controller

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	"github.com/xcode75/xcore/common/net"
	"github.com/xcode75/xcore/core"
	"github.com/xcode75/xcore/infra/conf"

	"github.com/xcode75/XMPlus/api"
	"github.com/xcode75/XMPlus/common/mylego"
)

// InboundBuilder build Inbound config for different protocol
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	inboundDetourConfig := &conf.InboundDetourConfig{}
	
	if nodeInfo.NodeType == "Shadowsocks-Plugin" {
		inboundDetourConfig.ListenOn = &conf.Address{Address: net.ParseAddress("127.0.0.1")}
	} else if nodeInfo.ListenIP != "" {
		ipAddress := net.ParseAddress(nodeInfo.ListenIP)
		inboundDetourConfig.ListenOn = &conf.Address{Address: ipAddress}
	}


	portList := &conf.PortList{
		Range: []conf.PortRange{{From: nodeInfo.Port, To: nodeInfo.Port}},
	}
	inboundDetourConfig.PortList = portList

	inboundDetourConfig.Tag = tag

	sniffingConfig := &conf.SniffingConfig{
		Enabled:      nodeInfo.Sniffing,
		DestOverride: &conf.StringList{"http", "tls"},
	}
	
	inboundDetourConfig.SniffingConfig = sniffingConfig

	var (
		protocol      string
		streamSetting *conf.StreamConfig
		setting       json.RawMessage
	)

	var proxySetting any
	// Build Protocol and Protocol setting
	switch nodeInfo.NodeType {
	case "Vless":
		protocol = "vless"
		// Enable fallback
		if nodeInfo.EnableFallback && nodeInfo.VlessFallBack != nil {
			proxySetting = &conf.VLessInboundConfig{
				Decryption: "none",
				Fallbacks:  nodeInfo.VlessFallBack,
			}
		} else {
			proxySetting = &conf.VLessInboundConfig{
				Decryption: "none",
			}
		}
	case "Vmess":	
		protocol = "vmess"
		proxySetting = &conf.VMessInboundConfig{}
	case "Trojan":
		protocol = "trojan"
		// Enable fallback
		if nodeInfo.EnableFallback  && nodeInfo.TrojanFallBack != nil  {
			proxySetting = &conf.TrojanServerConfig{
				Fallbacks: nodeInfo.TrojanFallBack,
			}
		} else {
			proxySetting = &conf.TrojanServerConfig{}
		}
	case "Shadowsocks", "Shadowsocks-Plugin":
		protocol = "shadowsocks"
		cipher := strings.ToLower(nodeInfo.CypherMethod)

		proxySetting = &conf.ShadowsocksServerConfig{
			Cipher:   cipher,
			Password: nodeInfo.ServerKey, // shadowsocks2022 shareKey
		}

		proxySetting, _ := proxySetting.(*conf.ShadowsocksServerConfig)
		
		// shadowsocks must have a random password
		// shadowsocks2022's password == user PSK, thus should a length of string >= 32 and base64 encoder
		
		b := make([]byte, 32)
		rand.Read(b)
		randPasswd := hex.EncodeToString(b)
		if C.Contains(shadowaead_2022.List, cipher) {
			proxySetting.Users = append(proxySetting.Users, &conf.ShadowsocksUserConfig{
				Password: base64.StdEncoding.EncodeToString(b),
			})
		} else {
			proxySetting.Password = randPasswd
		}

		proxySetting.NetworkList = &conf.NetworkList{"tcp", "udp"}
		proxySetting.IVCheck = false

	case "dokodemo-door":
		protocol = "dokodemo-door"
		proxySetting = struct {
			Host        string   `json:"address"`
			NetworkList []string `json:"network"`
		}{
			Host:        "v1.mux.cool",
			NetworkList: []string{"tcp", "udp"},
		}
	default:
		return nil, fmt.Errorf("Unsupported Node Type: %s", nodeInfo.NodeType)
	}

	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config fialed: %s", nodeInfo.NodeType, err)
	}
	inboundDetourConfig.Protocol = protocol
	inboundDetourConfig.Settings = &setting

	// Build streamSettings
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

	// Build TLS and XTLS settings
	if nodeInfo.EnableTLS && nodeInfo.CertMode != "none" {
		streamSetting.Security = nodeInfo.TLSType
		certFile, keyFile, err := getCertFile(config.CertConfig, nodeInfo.CertMode, nodeInfo.CertDomain)
		if err != nil {
			return nil, err
		}
		if nodeInfo.TLSType == "tls" {
			tlsSettings := &conf.TLSConfig{
				RejectUnknownSNI: nodeInfo.RejectUnknownSNI,
			}
			tlsSettings.Insecure = nodeInfo.AllowInsecure
			tlsSettings.ServerName = nodeInfo.CertDomain
			tlsSettings.Fingerprint = nodeInfo.Fingerprint
			tlsSettings.Certs = append(tlsSettings.Certs, &conf.TLSCertConfig{CertFile: certFile, KeyFile: keyFile, OcspStapling: 3600})

			streamSetting.TLSSettings = tlsSettings
		} else if nodeInfo.TLSType == "xtls" {
			xtlsSettings := &conf.XTLSConfig{
				RejectUnknownSNI: nodeInfo.RejectUnknownSNI,
			}
			xtlsSettings.Insecure = nodeInfo.AllowInsecure
			xtlsSettings.ServerName = nodeInfo.CertDomain
			xtlsSettings.Certs = append(xtlsSettings.Certs, &conf.XTLSCertConfig{CertFile: certFile, KeyFile: keyFile, OcspStapling: 3600})
			streamSetting.XTLSSettings = xtlsSettings
		}
	}

	// Support ProxyProtocol for any transport protocol
	if networkType != "tcp" && networkType != "ws" && nodeInfo.ProxyProtocol {
		sockoptConfig := &conf.SocketConfig{
			AcceptProxyProtocol: nodeInfo.ProxyProtocol,
		}
		streamSetting.SocketSettings = sockoptConfig
	}
	inboundDetourConfig.StreamSetting = streamSetting

	return inboundDetourConfig.Build()
}

func getCertFile(certConfig *mylego.CertConfig, CertMode string, Domain string) (certFile string, keyFile string, err error) {
	switch CertMode {
	case "file":
		if certConfig.CertFile == "" || certConfig.KeyFile == "" {
			return "", "", fmt.Errorf("Cert file path or key file path missing, check your config.yml parameters.")
		}
		return certConfig.CertFile, certConfig.KeyFile, nil
	case "dns":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.DNSCert(CertMode, Domain)
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	case "http", "tls":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.HTTPCert(CertMode, Domain)
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", CertMode)
	}
}