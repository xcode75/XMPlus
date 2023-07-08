package all

import (
	// The following are necessary as they register handlers in their init functions.

	_ "github.com/xcode75/xcore/app/proxyman/inbound"
	_ "github.com/xcode75/xcore/app/proxyman/outbound"

	// Required features. Can't remove unless there is replacements.
	// _ "github.com/xcode75/xcore/app/dispatcher"
	_ "github.com/xcode75/XMPlus/app/mydispatcher"

	// Default commander and all its services. This is an optional feature.
	_ "github.com/xcode75/xcore/app/commander"
	_ "github.com/xcode75/xcore/app/log/command"
	_ "github.com/xcode75/xcore/app/proxyman/command"
	_ "github.com/xcode75/xcore/app/stats/command"

	// Other optional features.
	_ "github.com/xcode75/xcore/app/dns"
	_ "github.com/xcode75/xcore/app/log"
	_ "github.com/xcode75/xcore/app/metrics"
	_ "github.com/xcode75/xcore/app/policy"
	_ "github.com/xcode75/xcore/app/reverse"
	_ "github.com/xcode75/xcore/app/router"
	_ "github.com/xcode75/xcore/app/stats"

	// Inbound and outbound proxies.
	_ "github.com/xcode75/xcore/proxy/blackhole"
	_ "github.com/xcode75/xcore/proxy/dns"
	_ "github.com/xcode75/xcore/proxy/dokodemo"
	_ "github.com/xcode75/xcore/proxy/freedom"
	_ "github.com/xcode75/xcore/proxy/http"
	_ "github.com/xcode75/xcore/proxy/shadowsocks"
	_ "github.com/xcode75/xcore/proxy/socks"
	_ "github.com/xcode75/xcore/proxy/trojan"
	_ "github.com/xcode75/xcore/proxy/vless/inbound"
	_ "github.com/xcode75/xcore/proxy/vless/outbound"
	_ "github.com/xcode75/xcore/proxy/vmess/inbound"
	_ "github.com/xcode75/xcore/proxy/vmess/outbound"

	// Transports
	_ "github.com/xcode75/xcore/transport/internet/domainsocket"
	_ "github.com/xcode75/xcore/transport/internet/http"
	_ "github.com/xcode75/xcore/transport/internet/kcp"
	_ "github.com/xcode75/xcore/transport/internet/quic"
	_ "github.com/xcode75/xcore/transport/internet/tcp"
	_ "github.com/xcode75/xcore/transport/internet/tls"
	_ "github.com/xcode75/xcore/transport/internet/udp"
	_ "github.com/xcode75/xcore/transport/internet/websocket"
	_ "github.com/xcode75/xcore/transport/internet/reality"

	// Transport headers
	_ "github.com/xcode75/xcore/transport/internet/headers/http"
	_ "github.com/xcode75/xcore/transport/internet/headers/noop"
	_ "github.com/xcode75/xcore/transport/internet/headers/srtp"
	_ "github.com/xcode75/xcore/transport/internet/headers/tls"
	_ "github.com/xcode75/xcore/transport/internet/headers/utp"
	_ "github.com/xcode75/xcore/transport/internet/headers/wechat"
	_ "github.com/xcode75/xcore/transport/internet/headers/wireguard"

	// JSON & TOML & YAML
	_ "github.com/xcode75/xcore/main/json"
	_ "github.com/xcode75/xcore/main/toml"
	_ "github.com/xcode75/xcore/main/yaml"

	// Load config from file or http(s)
	_ "github.com/xcode75/xcore/main/confloader/external"

	// Commands
	_ "github.com/xcode75/xcore/main/commands/all"
)
