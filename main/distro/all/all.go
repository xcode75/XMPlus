package all

import (
	// The following are necessary as they register handlers in their init functions.

	// Required features. Can't remove unless there is replacements.
	// _ "github.com/xcode75/XMCore/app/dispatcher"
	_ "github.com/xcode75/XMCore/app/proxyman/inbound"
	_ "github.com/xcode75/XMCore/app/proxyman/outbound"

	// Default commander and all its services. This is an optional feature.
	_ "github.com/xcode75/XMCore/app/commander"
	_ "github.com/xcode75/XMCore/app/log/command"
	_ "github.com/xcode75/XMCore/app/proxyman/command"
	_ "github.com/xcode75/XMCore/app/stats/command"
	_ "github.com/xcode75/XMCore/app/router/command"

	// Other optional features.
	_ "github.com/xcode75/XMCore/app/dns"
	_ "github.com/xcode75/XMCore/app/log"
	_ "github.com/xcode75/XMCore/app/policy"
	_ "github.com/xcode75/XMCore/app/reverse"
	_ "github.com/xcode75/XMCore/app/router"
	_ "github.com/xcode75/XMCore/app/stats"

	// Inbound and outbound proxies.
	_ "github.com/xcode75/XMCore/proxy/blackhole"
	_ "github.com/xcode75/XMCore/proxy/dns"
	_ "github.com/xcode75/XMCore/proxy/dokodemo"
	_ "github.com/xcode75/XMCore/proxy/freedom"
	_ "github.com/xcode75/XMCore/proxy/http"
	_ "github.com/xcode75/XMCore/proxy/mtproto"
	_ "github.com/xcode75/XMCore/proxy/shadowsocks"
	_ "github.com/xcode75/XMCore/proxy/socks"
	_ "github.com/xcode75/XMCore/proxy/trojan"
	_ "github.com/xcode75/XMCore/proxy/vless/inbound"
	_ "github.com/xcode75/XMCore/proxy/vless/outbound"
	_ "github.com/xcode75/XMCore/proxy/vmess/inbound"
	_ "github.com/xcode75/XMCore/proxy/vmess/outbound"

	// Transports
	_ "github.com/xcode75/XMCore/transport/internet/domainsocket"
	_ "github.com/xcode75/XMCore/transport/internet/http"
	_ "github.com/xcode75/XMCore/transport/internet/kcp"
	_ "github.com/xcode75/XMCore/transport/internet/quic"
	_ "github.com/xcode75/XMCore/transport/internet/tcp"
	_ "github.com/xcode75/XMCore/transport/internet/tls"
	_ "github.com/xcode75/XMCore/transport/internet/udp"
	_ "github.com/xcode75/XMCore/transport/internet/websocket"
	_ "github.com/xcode75/XMCore/transport/internet/xtls"

	// Transport headers
	_ "github.com/xcode75/XMCore/transport/internet/headers/http"
	_ "github.com/xcode75/XMCore/transport/internet/headers/noop"
	_ "github.com/xcode75/XMCore/transport/internet/headers/srtp"
	_ "github.com/xcode75/XMCore/transport/internet/headers/tls"
	_ "github.com/xcode75/XMCore/transport/internet/headers/utp"
	_ "github.com/xcode75/XMCore/transport/internet/headers/wechat"
	_ "github.com/xcode75/XMCore/transport/internet/headers/wireguard"

	// JSON & TOML & YAML
	_ "github.com/xcode75/XMCore/main/json"
	_ "github.com/xcode75/XMCore/main/toml"
	_ "github.com/xcode75/XMCore/main/yaml"

	// Load config from file or http(s)
	_ "github.com/xcode75/XMCore/main/confloader/external"

	// Commands
	_ "github.com/xcode75/XMCore/main/commands/all"
)
