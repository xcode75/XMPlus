package xmplus

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"
	"sync"
	"errors"
	"reflect"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
	"github.com/xcode75/xcore/common/net"
	"github.com/xcode75/xcore/infra/conf"

	"github.com/xcode75/XMPlus/api"
)


type APIClient struct {
	client        *resty.Client
	APIHost       string
	NodeID        int
	Key           string
	resp          atomic.Value
	eTag          string
	LastReportOnline   map[int]int
	access        sync.Mutex
}

func New(apiConfig *api.Config) *APIClient {
	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)
	
	client.SetQueryParam("key", apiConfig.Key)
	
	apiClient := &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		LastReportOnline:    make(map[int]int),
	}
	return apiClient
}


func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key}
}


func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*simplejson.Json, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() > 399 {
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %s", c.assembleURL(path), string(body), err)
	}
	rtn, err := simplejson.NewJson(res.Body())
	if err != nil {
		return nil, fmt.Errorf("%s", res.String())
	}
	return rtn, nil
}


func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	server := new(serverConfig)
	path := fmt.Sprintf("/api/v2/query/server/%d", c.NodeID)
	res, err := c.client.R().
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	
	b, _ := response.Encode()
	json.Unmarshal(b, server)
	
	if server.Port <= 0 {
		return nil, errors.New("server port must > 0")
	}
	
	c.resp.Store(server)
	
	nodeInfo, err = c.parseNodeResponse(server)
	if err != nil {
		return nil, fmt.Errorf("Parse node info failed: %s, \nError: %v", res.String(), err)
	}
	return nodeInfo, nil
}


func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	path := fmt.Sprintf("/api/v2/query/users/%d", c.NodeID)
	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTag).
		ForceContentType("application/json").
		Get(path)


	if res.StatusCode() == 304 {
		return nil, errors.New("users_no_change")
	}
	
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTag {
		c.eTag = res.Header().Get("Etag")
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	
	users := new([]User)
	
	b, _ := response.Get("users").Encode()
	json.Unmarshal(b, users)
	
	if err := json.Unmarshal(b, users); err != nil {
		return nil, fmt.Errorf("Unmarshal %s failed: %s", reflect.TypeOf(users), err)
	}
	
	userList, err := c.ParseUserListResponse(users)
	if err != nil {
		res, _ := json.Marshal(users)
		return nil, fmt.Errorf("Parse user list failed: %s", string(res))
	}

	return userList, nil
}

func (c *APIClient) ParseUserListResponse(userInfoResponse *[]User) (*[]api.UserInfo, error) {
	c.access.Lock()
	defer func() {
		c.LastReportOnline = make(map[int]int)
		c.access.Unlock()
	}()	
	
	var deviceLimit, onlineipcount, ipcount int = 0, 0, 0
	
	userList := []api.UserInfo{}
	
	for _, user := range *userInfoResponse {
		deviceLimit = user.Iplimit
		ipcount = user.Ipcount
		
		if deviceLimit > 0 && ipcount > 0 {
			lastOnline := 0
			if v, ok := c.LastReportOnline[user.Id]; ok {
				lastOnline = v
			}
			if onlineipcount = deviceLimit - ipcount + lastOnline; onlineipcount > 0 {
				deviceLimit = onlineipcount
			} else if lastOnline > 0 {
				deviceLimit = lastOnline
			} else {
				continue
			}
		}

		userList = append(userList, api.UserInfo{
			UID:  user.Id,
			UUID: user.Uuid,
			Email: user.Email,
			Passwd: user.Uuid,
			DeviceLimit: deviceLimit,
			SpeedLimit:  uint64(user.Speedlimit * 1000000 / 8),
		})
	}

	return &userList, nil
}


func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	routes := c.resp.Load().(*serverConfig).Routes
	
	Rules := len(routes)
	detects := make([]api.DetectRule, Rules)
	
	for i := range routes {
		ruleList := api.DetectRule{
			ID:      routes[i].Id,
			Pattern: regexp.MustCompile(routes[i].Regex),
		}
		detects[i] = ruleList
	}

	return &detects, nil
}


func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	path := fmt.Sprintf("/api/v2/query/users/traffic/%d", c.NodeID)

	data := make([]UserTraffic, len(*userTraffic))	
	for i, traffic := range *userTraffic {
		data[i] = UserTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download,
		}
	}
	postData := &PostData{Data: data}
	res, err := c.client.R().
		SetBody(postData).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}


func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	path := fmt.Sprintf("/api/v2/query/server/status/%d", c.NodeID)
	systemload := SystemLoad{
		Uptime: strconv.FormatUint(nodeStatus.Uptime, 10),
		Load:    fmt.Sprintf("%.2f %.2f %.2f", nodeStatus.CPU/100, nodeStatus.Mem/100, nodeStatus.Disk/100),
	}

	res, err := c.client.R().
		SetBody(systemload).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}


func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	c.access.Lock()
	defer c.access.Unlock()

	reportOnline := make(map[int]int)
	data := make([]OnlineUser, len(*onlineUserList))
	for i, user := range *onlineUserList {
		data[i] = OnlineUser{UID: user.UID, IP: user.IP}
		if _, ok := reportOnline[user.UID]; ok {
			reportOnline[user.UID]++
		} else {
			reportOnline[user.UID] = 1
		}
	}
	c.LastReportOnline = reportOnline // Update LastReportOnline

	postData := &PostData{Data: data}
	path := fmt.Sprintf("/api/v2/query/users/online/%d", c.NodeID)
	res, err := c.client.R().
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}


func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	data := make([]IllegalItem, len(*detectResultList))
	for i, r := range *detectResultList {
		data[i] = IllegalItem{
			ID:  r.RuleID,
			UID: r.UID,
		}
	}
	postData := &PostData{Data: data}
	path := fmt.Sprintf("/api/v2/query/server/detects/%d", c.NodeID)
	res, err := c.client.R().
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}
	return nil
}


func (c *APIClient) parseNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	var (
		TLSType                 = "none"
		path, host, quic_security, quic_key,serviceName,seed,htype string
		header                  json.RawMessage
		enableTLS,congestion    bool
		alterID                 uint16 = 0
	)
	
	Alpn := ""
	
	if s.SecuritySettings.Alpn != "" {
		Alpn = s.SecuritySettings.Alpn
	}
	
	Flow := "xtls-rprx-direct"
	
	if s.SecuritySettings.Flow == "xtls-rprx-vision" {
		Flow = "xtls-rprx-vision"
	}
	
	TLSType = s.Security
	
	if TLSType == "tls" || TLSType == "xtls" {
		enableTLS = true
		if s.SecuritySettings.ServerName == "" {
			return nil, fmt.Errorf("TLS certificate domain is empty: %s",  s.SecuritySettings.ServerName)
		}
	}

	transportProtocol := s.Network

	switch transportProtocol {
	case "ws":
		path = s.NetworkSettings.Path
		if headerHost, err := s.NetworkSettings.Headers.MarshalJSON(); err != nil {
				return nil, err
		} else {
			w, _ := simplejson.NewJson(headerHost)
			host = w.Get("Host").MustString()
		}
	case "h2":
		path = s.NetworkSettings.Path
		host = s.NetworkSettings.Host
	case "grpc":
		serviceName = s.NetworkSettings.ServiceName
	case "tcp":
		if httpHeader, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
		} else {
			t, _ := simplejson.NewJson(httpHeader)
			htype = t.Get("type").MustString()
			if htype == "http" {
				path = t.Get("request").Get("path").MustString()
				header, _ = json.Marshal(map[string]any{
					"type": "http",
					"request": map[string]any{
						"path": path,
					}})
			}else{
				header, _ = json.Marshal(map[string]any{
					"type": "none",
					})
			}
		}
	case "quic":
		quic_key = s.NetworkSettings.Quickey
		quic_security = s.NetworkSettings.QuicSecurity
		if headerType, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
		} else {
			h, _ := simplejson.NewJson(headerType)
			htype = h.Get("type").MustString()
		}
		header, _ = json.Marshal(map[string]any{
				"type": htype,
			})
	case "kcp":
		seed = s.NetworkSettings.Seed
		congestion = s.NetworkSettings.Congestion
		if headerType, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
		} else {
			k, _ := simplejson.NewJson(headerType)
			htype = k.Get("type").MustString()
		}
		header, _ = json.Marshal(map[string]any{
				"type": htype,
			})		
	}
	
	NodeType := s.Type
	
	if NodeType == "Shadowsocks"  && (transportProtocol == "ws" || transportProtocol == "grpc" || transportProtocol == "quic") {
		NodeType = "Shadowsocks-Plugin"
	}
	
	nodeInfo := &api.NodeInfo{
		NodeType:          NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(s.Port),
		TransportProtocol: transportProtocol,
		EnableTLS:         enableTLS,
		TLSType:           TLSType,
		Path:              path,
		Host:              host,
		ServiceName:       serviceName,
		Flow:              Flow,
		Header:            header,
		AlterID:           alterID,
		Seed:              seed,
		Congestion:        congestion,
		Sniffing:          s.Sniffing,
		RejectUnknownSNI:  s.SecuritySettings.RejectUnknownSni,
		Fingerprint:       s.SecuritySettings.Fingerprint, 
		Quic_security:     quic_security,
		Alpn:              Alpn,
		Quic_key:          quic_key,
		CypherMethod:      s.Cipher,
		Address:           s.Address, 
		AllowInsecure:     s.SecuritySettings.AllowInsecure,
		Relay:             s.Relay,
		RelayNodeID:       s.Relayid,
		ListenIP:          s.Listenip, 
		ProxyProtocol:     s.NetworkSettings.ProxyProtocol,
		CertMode:          s.Certmode,
		CertDomain:        s.SecuritySettings.ServerName,
		ServerKey:         s.ServerKey,
		SpeedLimit:        uint64(s.Speedlimit * 1000000 / 8),
		EnableFallback:    s.Fallback,
		EnableDNS:         s.EnableDns,
		DomainStrategy:    s.Domainstrategy,
		SendIP:            s.sendThrough,
		TrojanFallBack:    s.parseTrojanFallBack(),
		VlessFallBack:     s.parseVlessFallBack(),
		NameServerConfig:  s.parseDNSConfig(),
	}
	return nodeInfo, nil
}

func (s *serverConfig) parseDNSConfig() (nameServerList []*conf.NameServerConfig) {
	for i := range s.DNS {
		nameServerList = append(nameServerList, &conf.NameServerConfig{
			Address: &conf.Address{net.ParseAddress(s.DNS[i].Address)},
			Domains: s.DNS[i].Domain,
		})
	}

	return
}

func (s *serverConfig) parseTrojanFallBack() ([]*conf.TrojanInboundFallback) {
	numOffallbacks := len(s.Fallbacks)
	fallbackList := make([]*conf.TrojanInboundFallback, numOffallbacks)
	for i := 0; i < numOffallbacks; i++ {
		var dest json.RawMessage
		dest, err := json.Marshal(s.Fallbacks[i].Dest)
		if err != nil {
			return nil
		}
		u := &conf.TrojanInboundFallback{
			Name: s.Fallbacks[i].SNI,
			Alpn: s.Fallbacks[i].Alpn,
			Path: s.Fallbacks[i].Path,
			Dest: dest,
			Xver: uint64(s.Fallbacks[i].ProxyProtocol),
		}
		fallbackList[i] = u
	}

	return fallbackList
}

func (s *serverConfig) parseVlessFallBack() ([]*conf.VLessInboundFallback) {
	numOffallbacks := len(s.Fallbacks)
	fallbackList := make([]*conf.VLessInboundFallback, numOffallbacks)
	for i := 0; i < numOffallbacks; i++ {
		var dest json.RawMessage
		dest, err := json.Marshal(s.Fallbacks[i].Dest)
		if err != nil {
			return nil
		}
		u := &conf.VLessInboundFallback{
			Name: s.Fallbacks[i].SNI,
			Alpn: s.Fallbacks[i].Alpn,
			Path: s.Fallbacks[i].Path,
			Dest: dest,
			Xver: uint64(s.Fallbacks[i].ProxyProtocol),
		}
		fallbackList[i] = u
	}

	return fallbackList
}


func (c *APIClient) GetRelayNodeInfo() (*api.RelayNodeInfo, error) {
	s := c.resp.Load().(*serverConfig)
	
	var (
		TLSType                 = "none"
		path, host, quic_security, quic_key,serviceName,seed,htype string
		header                  json.RawMessage
		enableTLS,congestion    bool
		alterID                 uint16 = 0
	)

	Alpn := ""
	
	if s.RSecuritySettings.Alpn != "" {
		Alpn = s.RSecuritySettings.Alpn
	}
	
	Flow := "xtls-rprx-direct"
	
	if s.SecuritySettings.Flow == "xtls-rprx-vision" {
		Flow = "xtls-rprx-vision"
	}
	
	TLSType = s.RSecurity
	
	if TLSType == "tls" || TLSType == "xtls" {
		enableTLS = true
	}

	transportProtocol := s.RNetwork

	switch transportProtocol {
	case "ws":
		path = s.RNetworkSettings.Path
		if headerHost, err := s.RNetworkSettings.Headers.MarshalJSON(); err != nil {
				return nil, err
		} else {
			w, _ := simplejson.NewJson(headerHost)
			host = w.Get("Host").MustString()
		}
	case "h2":
		path = s.RNetworkSettings.Path
		host = s.RNetworkSettings.Host
	case "grpc":
		serviceName = s.RNetworkSettings.ServiceName
	case "tcp":
		if httpHeader, err := s.RNetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
		} else {
			t, _ := simplejson.NewJson(httpHeader)
			htype = t.Get("type").MustString()
			if htype == "http" {
				path = t.Get("request").Get("path").MustString()
				header, _ = json.Marshal(map[string]any{
					"type": "http",
					"request": map[string]any{
						"path": path,
					}})
			}else{
				header, _ = json.Marshal(map[string]any{
					"type": "none",
					})
			}
		}
	case "quic":
		quic_key = s.RNetworkSettings.Quickey
		quic_security = s.RNetworkSettings.QuicSecurity
		if headerType, err := s.RNetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
		} else {
			h, _ := simplejson.NewJson(headerType)
			htype = h.Get("type").MustString()
		}
		header, _ = json.Marshal(map[string]any{
				"type": htype,
			})
	case "kcp":
		seed = s.RNetworkSettings.Seed
		congestion = s.RNetworkSettings.Congestion
		if headerType, err := s.RNetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
		} else {
			k, _ := simplejson.NewJson(headerType)
			htype = k.Get("type").MustString()
		}
		header, _ = json.Marshal(map[string]any{
				"type": htype,
			})		
	}
	
	NodeType := s.RType
	
	if NodeType == "Shadowsocks"  && (transportProtocol == "ws" || transportProtocol == "grpc" || transportProtocol == "quic") {
		NodeType = "Shadowsocks-Plugin"
	}
	
	// Create GeneralNodeInfo
	nodeInfo := &api.RelayNodeInfo{
		NodeType:          NodeType,
		NodeID:            s.RServerid,
		Port:              uint32(s.RPort),
		TransportProtocol: transportProtocol,
		EnableTLS:         enableTLS,
		TLSType:           TLSType,
		Path:              path,
		Host:              host,
		Flow:              Flow,
		Seed :             seed,
		Congestion:        congestion,	
		ServiceName:       serviceName,
		Fingerprint:       s.RSecuritySettings.Fingerprint, 
		AllowInsecure:     s.RSecuritySettings.AllowInsecure,
		Header:            header,
		AlterID:           alterID,
		Alpn:              Alpn,
		Quic_security:     quic_security,
		Quic_key:          quic_key,
		CypherMethod:      s.RCipher,
		Address:           s.RAddress, 
		ListenIP:          s.RListenip, 
		ProxyProtocol:     s.RNetworkSettings.ProxyProtocol,
		ServerKey:         s.RServerKey,
		EnableDNS:         s.REnableDns,
		DomainStrategy:    s.RDomainstrategy,
		SendIP:            s.RsendThrough,
	}
	return nodeInfo, nil
}