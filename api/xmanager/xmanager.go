package xmanager

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"strconv"
	"time"
	"regexp"

	"github.com/xcode75/XMPlus/api"
	"github.com/go-resty/resty/v2"
)



// APIClient create a api client to the panel.
type APIClient struct {
	client        *resty.Client
	APIHost       string
	NodeID        int
	Key           string
	DeviceLimit   int
	LocalRuleList []api.DetectRule
}

// New creat a api instance
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
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)
	apiClient := &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: localRuleList,
	}
	return apiClient
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {

	LocalRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)

		//handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}

		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: regexp.MustCompile(fileScanner.Text()),
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Fatalf("Error while reading file: %s", err)
			return make([]api.DetectRule, 0)
		}

		file.Close()
	}

	return LocalRuleList
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

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*Response, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %s", c.assembleURL(path), string(body), err)
	}
	response := res.Result().(*Response)

	if response.Ret != 1 {
		res, _ := json.Marshal(&response)
		return nil, fmt.Errorf("API Response %s", string(res))
	}
	return response, nil
}

// GetNodeInfo will pull NodeInfo Config from xmanager
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	path := fmt.Sprintf("/api/v1/query/server/%d", c.NodeID)
	res, err := c.client.R().
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	nodeInfoResponse := new(NodeInfoResponse)

	if err := json.Unmarshal(response.Data, nodeInfoResponse); err != nil {
		return nil, fmt.Errorf("Unmarshal %s failed: %s", reflect.TypeOf(nodeInfoResponse), err)
	}
	
    nodeInfo, err = c.ParseNodeResponse(nodeInfoResponse)	

	if err != nil {
		res, _ := json.Marshal(nodeInfoResponse)
		return nil, fmt.Errorf("Parse node info failed: %s", string(res))
	}

	return nodeInfo, nil
}

// GetUserList will pull user form xmanager
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	path := "/api/v1/query/users"
	res, err := c.client.R().
		SetQueryParam("serverid", strconv.Itoa(c.NodeID)).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)

	userListResponse := new([]UserResponse)

	if err := json.Unmarshal(response.Data, userListResponse); err != nil {
		return nil, fmt.Errorf("Unmarshal %s failed: %s", reflect.TypeOf(userListResponse), err)
	}
	userList, err := c.ParseUserListResponse(userListResponse)
	if err != nil {
		res, _ := json.Marshal(userListResponse)
		return nil, fmt.Errorf("Parse user list failed: %s", string(res))
	}
	return userList, nil
}



// ReportNodeStatus reports the node status to the xmanager
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	path := fmt.Sprintf("/api/v1/update/server/status/%d", c.NodeID)
	systemload := SystemLoad{
		Uptime: strconv.FormatUint(nodeStatus.Uptime, 10),
		Load:   fmt.Sprintf("%.2f %.2f %.2f", nodeStatus.CPU/100, nodeStatus.CPU/100, nodeStatus.CPU/100),
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

//ReportNodeOnlineUsers reports online user ip
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	data := make([]OnlineUser, len(*onlineUserList))
	for i, user := range *onlineUserList {
		data[i] = OnlineUser{UID: user.UID, IP: user.IP}
	}

	postData := &PostData{Data: data}
	path := fmt.Sprintf("/api/v1/update/users/online/%d", c.NodeID)
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

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {

	data := make([]UserTraffic, len(*userTraffic))
	for i, traffic := range *userTraffic {
		data[i] = UserTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download}
	}
	postData := &PostData{Data: data}
	path := fmt.Sprintf("/api/v1/update/users/traffic/%d", c.NodeID)
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

// GetNodeRule will pull the audit rule form sspanel
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList
	path := "/api/v1/query/detect/rules"
	res, err := c.client.R().
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)

	ruleListResponse := new([]RuleItem)

	if err := json.Unmarshal(response.Data, ruleListResponse); err != nil {
		return nil, fmt.Errorf("Unmarshal %s failed: %s", reflect.TypeOf(ruleListResponse), err)
	}
	for _, r := range *ruleListResponse {
		ruleList = append(ruleList, api.DetectRule{
			ID:      r.ID,
			Pattern: regexp.MustCompile(r.Content),
		})
	}
	return &ruleList, nil
}

// ReportIllegal reports the user illegal behaviors
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {

	data := make([]IllegalItem, len(*detectResultList))
	for i, r := range *detectResultList {
		data[i] = IllegalItem{
			ID:  r.RuleID,
			UID: r.UID,
		}
	}
	postData := &PostData{Data: data}
	path := fmt.Sprintf("/api/v1/update/report/rules/%d", c.NodeID)
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


func (c *APIClient) ParseNodeResponse(nodeInfoResponse *NodeInfoResponse) (*api.NodeInfo, error) {
	var  enableTLS  bool
	var  speedlimit uint64 = 0
	var Type string
	var AlterID uint16 = 0
	
	port := nodeInfoResponse.Port
	Host := ""
	Path := ""
	HeaderType := "none"
	ServiceName := ""
	Method := ""
	
	Type = nodeInfoResponse.Type
	
	if nodeInfoResponse.Address == "" {
		return nil, fmt.Errorf("No server address in response")
	}
	
	if nodeInfoResponse.Security == "xtls" || nodeInfoResponse.Security == "tls"{
		enableTLS = true
	}
	
	if nodeInfoResponse.Protocol == "grpc" {
		ServiceName = nodeInfoResponse.ServiceName
	}

	if nodeInfoResponse.Protocol == "tcp" {
		HeaderType = nodeInfoResponse.Headertype
	}
	
	if HeaderType == "http" {
		Host = nodeInfoResponse.Host
	}
	
	if HeaderType == "" {
		HeaderType = "none"
	}
	
	if nodeInfoResponse.Protocol == "ws" || nodeInfoResponse.Protocol == "h2" {
		Path = nodeInfoResponse.Path
		Host = nodeInfoResponse.Host
	}	

	if nodeInfoResponse.Type == "Shadowsocks" {
		Method = nodeInfoResponse.Method
	}
	
	if nodeInfoResponse.Type == "Shadowsocks"  && nodeInfoResponse.Protocol == "ws" {
		port = port - 1
		if port <= 0 {
			return nil, fmt.Errorf("Shadowsocks-Plugin listen port must be greater than 1")
		}
		Type = "Shadowsocks-Plugin"
	}
	
	speedlimit = uint64((nodeInfoResponse.SpeedLimit * 1000000) / 8)

	nodeinfo := &api.NodeInfo{
		NodeType:          Type,
		NodeID:            c.NodeID,
		Port:              port,
		SpeedLimit:        speedlimit,
		AlterID:           AlterID,
		TransportProtocol: nodeInfoResponse.Protocol,
		EnableTLS:         enableTLS,
		TLSType:           nodeInfoResponse.Security,
		Path:              Path,
		Host:              Host,
		ServiceName:       ServiceName,
		HeaderType:        HeaderType,
		CypherMethod:      Method,
		Address:           nodeInfoResponse.Address,
		AllowInsecure:     nodeInfoResponse.AllowInsecure,
		RelayNodeID:       nodeInfoResponse.RelayNodeID,
		ListenIP:          nodeInfoResponse.ListenIP,
		ProxyProtocol:     nodeInfoResponse.ProxyProtocol,
		Sniffing:          nodeInfoResponse.Sniffing,
		RejectUnknownSNI:  nodeInfoResponse.RejectUnknownSNI,
		Fingerprint:       nodeInfoResponse.Fingerprint,
		Quic_security:     nodeInfoResponse.Quic_security,
		Quic_key:          nodeInfoResponse.Quic_key,
	}

	return nodeinfo, nil
}



func (c *APIClient) ParseUserListResponse(userInfoResponse *[]UserResponse) (*[]api.UserInfo, error) {

	var deviceLimit, onlintipcount int = 0, 0
	var speedlimit uint64 = 0

	userList := []api.UserInfo{}
	for _, user := range *userInfoResponse {
	
		if c.DeviceLimit > 0 {
			deviceLimit = c.DeviceLimit
		} else {
			deviceLimit = user.DeviceLimit
		}
		
		if user.LimitType == 1{
			if deviceLimit > 0 {
				if onlintipcount = deviceLimit - user.IPcount; onlintipcount < 0 {
					continue
				}else {
					deviceLimit = onlintipcount
				}
			}
		}
		
		speedlimit = uint64((user.SpeedLimit * 1000000) / 8)

		userList = append(userList, api.UserInfo{
			UID:           user.ID,
			Email:         user.Email,
			UUID:          user.UUID,
			Passwd:        user.Passwd,
			SpeedLimit:    speedlimit,
			DeviceLimit:   deviceLimit,
		})
	}

	return &userList, nil
}


// GetNodeInfo will pull GetTransitNodeInfo Config from xmanager
func (c *APIClient) GetTransitNodeInfo() (transitnodeinfo *api.TransitNodeInfo, err error) {
	path := fmt.Sprintf("/api/v1/query/server/transit/%d", c.NodeID)
	res, err := c.client.R().
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	nodeResponse := new(TransitNodeInfoResponse)

	if err := json.Unmarshal(response.Data, nodeResponse); err != nil {
		return nil, fmt.Errorf("Unmarshal %s failed: %s", reflect.TypeOf(nodeResponse), err)
	}

    transitnodeinfo, err = c.ParseTransitNodeResponse(nodeResponse)	

	if err != nil {
		res, _ := json.Marshal(nodeResponse)
		return nil, fmt.Errorf("Parse relay node info failed: %s", string(res))
	}

	return transitnodeinfo, nil
}



func (c *APIClient) ParseTransitNodeResponse(nodeInfoResponse *TransitNodeInfoResponse) (*api.TransitNodeInfo, error) {
	var enableTLS  bool
	var speedlimit uint64 = 0
	var Type string
	var AlterID uint16 = 0
	
	port := nodeInfoResponse.Port
	Host := ""
	Path := ""
	HeaderType := "none"
	ServiceName := ""
	Method := ""
	Flow := "none"
	
	Type = nodeInfoResponse.Type
	
	if nodeInfoResponse.Address == "" {
		return nil, fmt.Errorf("No server address in response")
	}
	
	if nodeInfoResponse.Security == "xtls" || nodeInfoResponse.Security == "tls"{
		enableTLS = true
	}
	
	if nodeInfoResponse.Protocol == "grpc" {
		ServiceName = nodeInfoResponse.ServiceName
		Flow = "xtls-rprx-direct"
	}

	if nodeInfoResponse.Protocol == "tcp" {
		HeaderType = nodeInfoResponse.Headertype
	}
	
	if HeaderType == "http" {
		Host = nodeInfoResponse.Host
	}
	
	if HeaderType == "" {
		HeaderType = "none"
	}
	
	if nodeInfoResponse.Protocol == "ws" || nodeInfoResponse.Protocol == "h2" {
		Path = nodeInfoResponse.Path
		Host = nodeInfoResponse.Host
	}	

	if nodeInfoResponse.Type == "Shadowsocks" {
		Method = nodeInfoResponse.Method
	}
	
	if nodeInfoResponse.Type == "Shadowsocks"  && (nodeInfoResponse.Protocol == "ws" || nodeInfoResponse.Protocol == "quic" || nodeInfoResponse.Protocol == "grpc") {
		port = port - 1
		if port <= 0 {
			return nil, fmt.Errorf("Shadowsocks-Plugin listen port must be greater than 1")
		}
		Type = "Shadowsocks-Plugin"
	}
	
	speedlimit = uint64((nodeInfoResponse.SpeedLimit * 1000000) / 8)

	nodeinfo := &api.TransitNodeInfo{
		NodeType:          Type,
		NodeID:            nodeInfoResponse.NodeID,
		Port:              port,
		SpeedLimit:        speedlimit,
		AlterID:           AlterID,
		TransportProtocol: nodeInfoResponse.Protocol,
		EnableTLS:         enableTLS,
		TLSType:           nodeInfoResponse.Security,
		Path:              Path,
		Host:              Host,
		ServiceName:       ServiceName,
		HeaderType:        HeaderType,
		CypherMethod:      Method,
		Flow:              Flow,
		Address:           nodeInfoResponse.Address,
		AllowInsecure:     nodeInfoResponse.AllowInsecure,
		ListenIP:          nodeInfoResponse.ListenIP,
		ProxyProtocol:     nodeInfoResponse.ProxyProtocol,
		Sniffing:          nodeInfoResponse.Sniffing,
		RejectUnknownSNI:  nodeInfoResponse.RejectUnknownSNI,
		Fingerprint:       nodeInfoResponse.Fingerprint,
		Quic_security:     nodeInfoResponse.Quic_security,
		Quic_key:          nodeInfoResponse.Quic_key,
	}

	return nodeinfo, nil
}
