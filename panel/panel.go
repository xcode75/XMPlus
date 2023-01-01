package panel

import (
	"encoding/json"
	io "io/ioutil"
	"log"
	"sync"

	"github.com/xcode75/XMPlus/api"
	"github.com/xcode75/XMPlus/api/xmanager"
	"github.com/xcode75/XMPlus/app/mydispatcher"
	_ "github.com/xcode75/XMPlus/main/distro/all"
	"github.com/xcode75/XMPlus/service"
	"github.com/xcode75/XMPlus/service/controller"
	"github.com/imdario/mergo"
	"github.com/r3labs/diff/v2"
	"github.com/xcode75/XMCore/app/proxyman"
	"github.com/xcode75/XMCore/app/stats"
	"github.com/xcode75/XMCore/common/serial"
	"github.com/xcode75/XMCore/core"
	"github.com/xcode75/XMCore/infra/conf"
)

// Panel Structure
type Panel struct {
	access      sync.Mutex
	panelConfig *Config
	Server      *core.Instance
	Service     []service.Service
	Running     bool
}

func New(panelConfig *Config) *Panel {
	p := &Panel{panelConfig: panelConfig}
	return p
}

func (p *Panel) loadCore(panelConfig *Config) *core.Instance {
	// Log Config
	coreLogConfig := &conf.LogConfig{}
	logConfig := getDefaultLogConfig()
	if panelConfig.LogConfig != nil {
		if _, err := diff.Merge(logConfig, panelConfig.LogConfig, logConfig); err != nil {
			log.Panicf("Read Log config failed: %s", err)
		}
	}
	coreLogConfig.LogLevel = logConfig.Level
	coreLogConfig.AccessLog = logConfig.AccessPath
	coreLogConfig.ErrorLog = logConfig.ErrorPath

	// DNS config
	coreDnsConfig := &conf.DNSConfig{}
	if panelConfig.DnsConfigPath != "" {
		if data, err := io.ReadFile(panelConfig.DnsConfigPath); err != nil {
			log.Panicf("Failed to read DNS config file at: %s", panelConfig.DnsConfigPath)
		} else {
			if err = json.Unmarshal(data, coreDnsConfig); err != nil {
				log.Panicf("Failed to unmarshal DNS config file: %s", panelConfig.DnsConfigPath)
			}
		}
	}
	dnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		log.Panicf("Failed to read dns.json, Please check: https://xtls.github.io/config/base/dns/ for help: %s", err)
	}

// Routing config
	coreRouterConfig := &conf.RouterConfig{}
	if panelConfig.RouteConfigPath != "" {
		if data, err := io.ReadFile(panelConfig.RouteConfigPath); err != nil {
			log.Panicf("Failed to read Routing config file: %s", panelConfig.RouteConfigPath)
		} else {
			if err = json.Unmarshal(data, coreRouterConfig); err != nil {
				log.Panicf("Failed to unmarshal Routing config file: %s", panelConfig.RouteConfigPath)
			}
		}
	}

	routeConfig, err := coreRouterConfig.Build()
	if err != nil {
		log.Panicf("Failed to read route.json, Please check: https://xtls.github.io/config/base/routing/ for help: %s", err)
	}
	// Custom Outbound config
	coreCustomOutboundConfig := []conf.OutboundDetourConfig{}
	if panelConfig.OutboundConfigPath != "" {
		if data, err := io.ReadFile(panelConfig.OutboundConfigPath); err != nil {
			log.Panicf("Failed to read Custom Inbound config file at: %s", panelConfig.OutboundConfigPath)
		} else {
			if err = json.Unmarshal(data, &coreCustomOutboundConfig); err != nil {
				log.Panicf("Failed to unmarshal Custom outbound config file: %s", panelConfig.OutboundConfigPath)
			}
		}
	}
	outBoundConfig := []*core.OutboundHandlerConfig{}
	for _, config := range coreCustomOutboundConfig {
		oc, err := config.Build()
		if err != nil {
			log.Panicf("Failed to read outbound.json, Please check: https://xtls.github.io/config/base/outbounds/ for help: %s", err)
		}
		outBoundConfig = append(outBoundConfig, oc)
	}	
	
	// Policy config
	levelPolicyConfig := parseConnectionConfig(panelConfig.ConnetionConfig)
	corePolicyConfig := &conf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*conf.Policy{0: levelPolicyConfig}
	policyConfig, _ := corePolicyConfig.Build()
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&mydispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Outbound: outBoundConfig,
	}
	server, err := core.New(config)
	if err != nil {
		log.Panicf("failed to create instance: %s", err)
	}
	//log.Printf("XMCore Version: %s", core.Version())

	return server
}

// Start Start the panel
func (p *Panel) Start() {
	p.access.Lock()
	defer p.access.Unlock()
	// Load Core
	server := p.loadCore(p.panelConfig)
	if err := server.Start(); err != nil {
		log.Panicf("Failed to Start Instance: %s", err)
	}
	log.Print("Instance Started Successfully")
	p.Server = server
	
	log.Print("XMPlus Started")
	// Load Nodes config
	for _, nodeConfig := range p.panelConfig.NodesConfig {
		var apiClient api.API
		apiClient = xmanager.New(nodeConfig.ApiConfig)
		
		var controllerService service.Service
		// Regist controller service
		controllerConfig := getDefaultControllerConfig()
		if nodeConfig.ControllerConfig != nil {
			if err := mergo.Merge(controllerConfig, nodeConfig.ControllerConfig, mergo.WithOverride); err != nil {
				log.Panicf("Read Controller Config Failed")
			}
		}
		controllerService = controller.New(server, apiClient, controllerConfig)
		p.Service = append(p.Service, controllerService)

	}

	// Start all the service
	for _, s := range p.Service {
		err := s.Start()
		if err != nil {
			log.Panicf("XMPlus Service Failed: %s", err)
		}
	}	
	p.Running = true
	return
}

// Close Close the panel
func (p *Panel) Close() {
	p.access.Lock()
	defer p.access.Unlock()
	for _, s := range p.Service {
		err := s.Close()
		if err != nil {
			log.Panicf("XMPlus Service Close, Failed: %s", err)
		}
	}
	p.Service = nil
	p.Server.Close()
	p.Running = false
	return
}

func parseConnectionConfig(c *ConnetionConfig) (policy *conf.Policy) {
	connetionConfig := getDefaultConnetionConfig()
	if c != nil {
		if _, err := diff.Merge(connetionConfig, c, connetionConfig); err != nil {
			log.Panicf("Read ConnetionConfig failed: %s", err)
		}
	}
	policy = &conf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         &connetionConfig.Handshake,
		ConnectionIdle:    &connetionConfig.ConnIdle,
		UplinkOnly:        &connetionConfig.UplinkOnly,
		DownlinkOnly:      &connetionConfig.DownlinkOnly,
		BufferSize:        &connetionConfig.BufferSize,
	}

	return
}