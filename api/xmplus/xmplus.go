package xmplus

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"sync"
	"errors"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
	"github.com/xcode75/xcore/common/net"
	"github.com/xcode75/xcore/infra/conf"

	"github.com/xcode75/XMPlus/api"
)

// APIClient create an api client to the panel.
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

// New create an api instance
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
	
	// Create Key for each requests
	client.SetQueryParam("key", apiConfig.Key)
	
	// apiClient
	apiClient := &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		LastReportOnline:    make(map[int]int),
	}
	return apiClient
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key}
}

// Debug set the client debug for client
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

// GetNodeInfo will pull NodeInfo Config from panel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	path := fmt.Sprintf("/api/v2/query/server/%d", c.NodeID)
	res, err := c.client.R().
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	c.resp.Store(response)
	nodeInfo, err = c.parseNodeResponse(response)
	if err != nil {
		res, _ := response.MarshalJSON()
		return nil, fmt.Errorf("Parse node info failed: %s, \nError: %s", string(res), err)
	}
	return nodeInfo, nil
}

// GetUserList will pull user form panel
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	var users []*User
	path := fmt.Sprintf("/api/v2/query/users/%d", c.NodeID)
	
	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTag).
		ForceContentType("application/json").
		Get(path)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New("users_no_change")
	}
	
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTag {
		c.eTag = res.Header().Get("Etag")
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	b, _ := response.Get("users").Encode()
	json.Unmarshal(b, &users)

	userList := make([]api.UserInfo, len(users))
	var deviceLimit, onlineipcount, ipcount int = 0, 0, 0
	
	c.access.Lock()
	// Clear Last report log
	defer func() {
		c.LastReportOnline = make(map[int]int)
		c.access.Unlock()
	}()	
	
	for i := 0; i < len(users); i++ {
		u := api.UserInfo{
			UID:  users[i].Id,
			UUID: users[i].Uuid,
			Email: users[i].Email,
			Passwd: users[i].Uuid,
			SpeedLimit:  uint64(users[i].Speedlimit * 1000000 / 8),
		}
		
		deviceLimit = users[i].Iplimit
		ipcount = users[i].Ipcount
		
		if deviceLimit > 0 && ipcount > 0 {
			lastOnline := 0
			if v, ok := c.LastReportOnline[users[i].Id]; ok {
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
		
		u.DeviceLimit = deviceLimit
		
		userList[i] = u
	}

	return &userList, nil
}

// GetNodeRule implements the API interface
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	
	nodeInfoResponse := c.resp.Load().(*simplejson.Json)	
	
	numOfRules := len(nodeInfoResponse.Get("routes").MustArray())
	detects := make([]api.DetectRule, numOfRules)
	
	for i := 0; i < numOfRules; i++ {
		detect := nodeInfoResponse.Get("routes").GetIndex(i)
	
		ruleList := api.DetectRule{
			ID:      detect.Get("id").MustInt(),
			Pattern: regexp.MustCompile(detect.Get("regex").MustString()),
		}
		detects[i] = ruleList
	}

	return &detects, nil
}

// ReportUserTraffic reports the user traffic
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

// ReportNodeStatus implements the API interface
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

// ReportNodeOnlineUsers implements the API interface
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

// ReportIllegal implements the API interface
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

// parseNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseNodeResponse(nodeInfoResponse *simplejson.Json) (*api.NodeInfo, error) {

	var (
		TLSType                 = "none"
		path, host, quic_security, quic_key,serviceName,seed,htype string
		header                  json.RawMessage
		enableTLS,congestion    bool
		alterID                 uint16 = 0
	)

	Flow := "xtls-rprx-direct"
	
	if data, ok := nodeInfoResponse.Get("relay_server").Get("securitySettings").CheckGet("flow"); ok  {
		if data.MustString() == "xtls-rprx-vision" {
			Flow = data.MustString()
		}
	}
	
	TLSType = nodeInfoResponse.Get("server").Get("security").MustString()
	
	if TLSType == "tls" || TLSType == "xtls" {
		enableTLS = true
	}

	transportProtocol := nodeInfoResponse.Get("server").Get("network").MustString()

	switch transportProtocol {
	case "ws":
		path = nodeInfoResponse.Get("server").Get("networkSettings").Get("path").MustString()
		host = nodeInfoResponse.Get("server").Get("networkSettings").Get("headers").Get("Host").MustString()
	case "h2":
		path = nodeInfoResponse.Get("server").Get("networkSettings").Get("path").MustString()
		host = nodeInfoResponse.Get("server").Get("networkSettings").Get("host").MustString()
	case "grpc":
		if data, ok := nodeInfoResponse.Get("server").Get("networkSettings").CheckGet("serviceName"); ok {
			serviceName = data.MustString()
		}
	case "tcp":
		if nodeInfoResponse.Get("server").Get("networkSettings").Get("header").Get("type").MustString() == "http" {
			path := "/"
			if p := nodeInfoResponse.Get("server").Get("networkSettings").Get("header").Get("request").Get("path").MustString(); p != "" {
				path = p
			}
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
	case "quic":
		quic_key = nodeInfoResponse.Get("server").Get("networkSettings").Get("key").MustString()
		quic_security = nodeInfoResponse.Get("server").Get("networkSettings").Get("security").MustString()
		htype = nodeInfoResponse.Get("server").Get("networkSettings").Get("header").Get("type").MustString()
		header, _ = json.Marshal(map[string]any{
				"type": htype,
			})
	case "kcp":
		seed = nodeInfoResponse.Get("server").Get("networkSettings").Get("seed").MustString()
		congestion = nodeInfoResponse.Get("server").Get("networkSettings").Get("congestion").MustBool()
		htype = nodeInfoResponse.Get("server").Get("networkSettings").Get("header").Get("type").MustString()
		header, _ = json.Marshal(map[string]any{
				"type": htype,
			})		
	}
	
	NodeType := nodeInfoResponse.Get("server").Get("type").MustString()
	
	if NodeType == "Shadowsocks"  && (transportProtocol == "ws" || transportProtocol == "grpc" || transportProtocol == "quic") {
		NodeType = "Shadowsocks-Plugin"
	}
	
	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(nodeInfoResponse.Get("server").Get("listeningport").MustUint64()),
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
		Sniffing:          nodeInfoResponse.Get("server").Get("sniffing").MustBool(),
		RejectUnknownSNI:  nodeInfoResponse.Get("server").Get("securitySettings").Get("rejectUnknownSni").MustBool(),
		Fingerprint:       nodeInfoResponse.Get("server").Get("securitySettings").Get("fingerprint").MustString(), 
		Quic_security:     quic_security,
		Quic_key:          quic_key,
		CypherMethod:      nodeInfoResponse.Get("server").Get("cipher").MustString(),
		Address:           nodeInfoResponse.Get("server").Get("address").MustString(), 
		AllowInsecure:     nodeInfoResponse.Get("server").Get("securitySettings").Get("allowInsecure").MustBool(),
		Relay:             nodeInfoResponse.Get("relay").MustBool(),
		RelayNodeID:       nodeInfoResponse.Get("server").Get("relayid").MustInt(),
		ListenIP:          nodeInfoResponse.Get("server").Get("listenip").MustString(), 
		ProxyProtocol:     nodeInfoResponse.Get("server").Get("networkSettings").Get("acceptProxyProtocol").MustBool(),
		CertMode:          nodeInfoResponse.Get("server").Get("certmode").MustString(),
		CertDomain:        nodeInfoResponse.Get("server").Get("securitySettings").Get("serverName").MustString(),
		ServerKey:         nodeInfoResponse.Get("server").Get("server_key").MustString(),
		SpeedLimit:        nodeInfoResponse.Get("server").Get("speedlimit").MustUint64() * 1000000 / 8,
		EnableFallback:    nodeInfoResponse.Get("fallback").MustBool(),
		EnableDNS:         nodeInfoResponse.Get("server").Get("enable_dns").MustBool(),
		DomainStrategy:    nodeInfoResponse.Get("server").Get("domainstrategy").MustString(),
		SendIP:            nodeInfoResponse.Get("server").Get("sendthrough").MustString(),
		TrojanFallBack:    parseTrojanFallBack(nodeInfoResponse),
		VlessFallBack:     parseVlessFallBack(nodeInfoResponse),
		NameServerConfig:  parseDNSConfig(nodeInfoResponse),
	}
	return nodeInfo, nil
}

func parseDNSConfig(nodeInfoResponse *simplejson.Json) (nameServerList []*conf.NameServerConfig) {
	for _, rule := range nodeInfoResponse.Get("dns").MustArray() {
		r := rule.(map[string]any)
			nameServerList = append(nameServerList, &conf.NameServerConfig{
				Address: &conf.Address{net.ParseAddress(r["address"].(string))},
				Domains: strings.Split(r["domain"].(string), ","),
			})
	}

	return
}

func parseTrojanFallBack(nodeInfoResponse *simplejson.Json) ([]*conf.TrojanInboundFallback) {
	numOffallbacks := len(nodeInfoResponse.Get("fallbacks").MustArray())
	fallbackList := make([]*conf.TrojanInboundFallback, numOffallbacks)
	for i := 0; i < numOffallbacks; i++ {
		fallback := nodeInfoResponse.Get("fallbacks").GetIndex(i)
		
		var dest json.RawMessage
		dest, err := json.Marshal(fallback.Get("dest").MustString())
		if err != nil {
			return nil
		}
		u := &conf.TrojanInboundFallback{
			Name: fallback.Get("sni").MustString(),
			Alpn: fallback.Get("alpn").MustString(),
			Path: fallback.Get("path").MustString(),
			Dest: dest,
			Xver: fallback.Get("proxyprotocolver").MustUint64(),
		}
		fallbackList[i] = u
	}

	return fallbackList
}

func parseVlessFallBack(nodeInfoResponse *simplejson.Json) ([]*conf.VLessInboundFallback) {
	numOffallbacks := len(nodeInfoResponse.Get("fallbacks").MustArray())
	fallbackList := make([]*conf.VLessInboundFallback, numOffallbacks)
	for i := 0; i < numOffallbacks; i++ {
		fallback := nodeInfoResponse.Get("fallbacks").GetIndex(i)
		
		var dest json.RawMessage
		dest, err := json.Marshal(fallback.Get("dest").MustString())
		if err != nil {
			return nil
		}
		u := &conf.VLessInboundFallback{
			Name: fallback.Get("sni").MustString(),
			Alpn: fallback.Get("alpn").MustString(),
			Path: fallback.Get("path").MustString(),
			Dest: dest,
			Xver: fallback.Get("proxyprotocolver").MustUint64(),
		}
		fallbackList[i] = u
	}

	return fallbackList
}

// GetRelayNodeInfo implements the API interface
func (c *APIClient) GetRelayNodeInfo() (*api.RelayNodeInfo, error) {
	nodeInfoResponse := c.resp.Load().(*simplejson.Json)
	
	var (
		TLSType                 = "none"
		path, host, quic_security, quic_key,serviceName,seed,htype string
		header                  json.RawMessage
		enableTLS,congestion    bool
		alterID                 uint16 = 0
	)

	Flow := "xtls-rprx-direct"
	
	if data, ok := nodeInfoResponse.Get("relay_server").Get("securitySettings").CheckGet("flow"); ok  {
		if data.MustString() == "xtls-rprx-vision" {
			Flow = data.MustString()
		}
	}
	
	TLSType = nodeInfoResponse.Get("relay_server").Get("security").MustString()
	
	if TLSType == "tls" || TLSType == "xtls" {
		enableTLS = true
	}

	transportProtocol := nodeInfoResponse.Get("relay_server").Get("network").MustString()

	switch transportProtocol {
	case "ws":
		path = nodeInfoResponse.Get("relay_server").Get("networkSettings").Get("path").MustString()
		host = nodeInfoResponse.Get("relay_server").Get("networkSettings").Get("headers").Get("Host").MustString()
	case "h2":
		path = nodeInfoResponse.Get("relay_server").Get("networkSettings").Get("path").MustString()
		host = nodeInfoResponse.Get("relay_server").Get("networkSettings").Get("host").MustString()
	case "grpc":
		if data, ok := nodeInfoResponse.Get("relay_server").Get("networkSettings").CheckGet("serviceName"); ok {
			serviceName = data.MustString()
		}
	case "tcp":
		if nodeInfoResponse.Get("relay_server").Get("networkSettings").Get("header").Get("type").MustString() == "http" {
			path := "/"
			if p := nodeInfoResponse.Get("server").Get("networkSettings").Get("header").Get("request").Get("path").MustString(); p != "" {
				path = p
			}
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
	case "quic":
		quic_key = nodeInfoResponse.Get("relay_server").Get("networkSettings").Get("key").MustString()
		quic_security = nodeInfoResponse.Get("relay_server").Get("networkSettings").Get("security").MustString()
		htype = nodeInfoResponse.Get("server").Get("networkSettings").Get("header").Get("type").MustString()
		header, _ = json.Marshal(map[string]any{
				"type": htype,
			})
	case "kcp":
		seed = nodeInfoResponse.Get("server").Get("networkSettings").Get("seed").MustString()
		congestion = nodeInfoResponse.Get("server").Get("networkSettings").Get("congestion").MustBool()
		htype = nodeInfoResponse.Get("server").Get("networkSettings").Get("header").Get("type").MustString()
		header, _ = json.Marshal(map[string]any{
				"type": htype,
			})			
	}
	
	NodeType := nodeInfoResponse.Get("relay_server").Get("type").MustString()
	
	if NodeType == "Shadowsocks"  && (transportProtocol == "ws" || transportProtocol == "grpc" || transportProtocol == "quic") {
		NodeType = "Shadowsocks-Plugin"
	}
	
	// Create GeneralNodeInfo
	nodeInfo := &api.RelayNodeInfo{
		NodeType:          NodeType,
		NodeID:            nodeInfoResponse.Get("relay_server").Get("serverid").MustInt(),
		Port:              uint32(nodeInfoResponse.Get("relay_server").Get("listeningport").MustUint64()),
		TransportProtocol: transportProtocol,
		EnableTLS:         enableTLS,
		TLSType:           TLSType,
		Path:              path,
		Host:              host,
		Flow:              Flow,
		Seed :             seed,
		Congestion:        congestion,	
		ServiceName:       serviceName,
		AllowInsecure:     nodeInfoResponse.Get("relay_server").Get("securitySettings").Get("allowInsecure").MustBool(),
		Header:            header,
		AlterID:           alterID,
		Quic_security:     quic_security,
		Quic_key:          quic_key,
		CypherMethod:      nodeInfoResponse.Get("relay_server").Get("cipher").MustString(),
		Address:           nodeInfoResponse.Get("relay_server").Get("address").MustString(), 
		ListenIP:          nodeInfoResponse.Get("relay_server").Get("listenip").MustString(), 
		ProxyProtocol:     nodeInfoResponse.Get("relay_server").Get("networkSettings").Get("acceptProxyProtocol").MustBool(),
		ServerKey:         nodeInfoResponse.Get("relay_server").Get("server_key").MustString(),
		EnableDNS:         nodeInfoResponse.Get("relay_server").Get("enable_dns").MustBool(),
		DomainStrategy:    nodeInfoResponse.Get("relay_server").Get("domainstrategy").MustString(),
		SendIP:            nodeInfoResponse.Get("relay_server").Get("sendthrough").MustString(),
	}
	return nodeInfo, nil
}