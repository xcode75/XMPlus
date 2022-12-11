package controller

import (
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/xcode75/XMPlus/api"
	"github.com/xcode75/XMPlus/app/mydispatcher"
	"github.com/xcode75/XMPlus/common/legocmd"
	"github.com/xcode75/XMPlus/common/serverstatus"
	"github.com/xcode75/XMCore/common/protocol"
	"github.com/xcode75/XMCore/common/task"
	"github.com/xcode75/XMCore/core"
	"github.com/xcode75/XMCore/features/stats"
	"github.com/xcode75/XMCore/features/inbound"
	"github.com/xcode75/XMCore/features/outbound"
	"github.com/xcode75/XMCore/features/routing"
)

type Controller struct {
	server                  *core.Instance
	config                  *Config
	clientInfo              api.ClientInfo
	apiClient               api.API
	nodeInfo                *api.NodeInfo
	transitnodeInfo         *api.TransitNodeInfo
	Tag                     string
	TransitTag              string
	Rtag                    bool
	userList                *[]api.UserInfo
	nodeInfoMonitorPeriodic *task.Periodic
	userReportPeriodic      *task.Periodic
	ihm                     inbound.Manager
	ohm                     outbound.Manager
	stm                     stats.Manager
	dispatcher              *mydispatcher.DefaultDispatcher
}

// New return a Controller service with default parameters.
func New(server *core.Instance, api api.API, config *Config) *Controller {
	controller := &Controller{
		server:    server,
		config:    config,
		apiClient: api,
		ihm:        server.GetFeature(inbound.ManagerType()).(inbound.Manager),
		ohm:        server.GetFeature(outbound.ManagerType()).(outbound.Manager),
		stm:        server.GetFeature(stats.ManagerType()).(stats.Manager),
		dispatcher: server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher),
	}
	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	
	c.clientInfo = c.apiClient.Describe()
	
	// First fetch Node Info
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	c.nodeInfo = newNodeInfo

	
	// Update user
	userInfo, err := c.apiClient.GetUserList()
	if err != nil {
		return err
	}	
	c.userList = userInfo
	c.Tag = c.buildTag()
		
	c.Rtag = false
	
	// Add new Transit	tag
	if c.nodeInfo.RelayNodeID > 0 {	
	
		newTransitNodeInfo, err := c.apiClient.GetTransitNodeInfo()
		if err != nil {
			log.Panic(err)
			return nil
		}	
		c.transitnodeInfo = newTransitNodeInfo
		c.TransitTag = c.buildRTag()
		err = c.Transit(newTransitNodeInfo, userInfo)
		if err != nil {
				log.Panic(err)
				return err
		}
		c.Rtag = true
	}
	
	// Add new tag
	err = c.addNewTag(newNodeInfo)
	if err != nil {
		log.Panic(err)
		return err
	}
		
	err = c.addNewUser(userInfo, newNodeInfo)
	if err != nil {
		return err
	}

	// Add Limiter
	if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, userInfo); err != nil {
		log.Print(err)
	}
	
	// Add Rule Manager
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			log.Printf("Get rule list filed: %s", err)
		} else if len(*ruleList) > 0 {
			if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
				log.Print(err)
			}
		}
	}
	
	c.nodeInfoMonitorPeriodic = &task.Periodic{
		Interval: time.Duration(60) * time.Second,
		Execute:  c.nodeInfoMonitor,
	}
	
	c.userReportPeriodic = &task.Periodic{
		Interval: time.Duration(60) * time.Second,
		Execute:  c.userInfoMonitor,
	}
	
	log.Printf("【NodeType：%s | NodeID: %d 】Task Scheduler Started", c.nodeInfo.NodeType,c.nodeInfo.NodeID)
	c.nodeInfoMonitorPeriodic.Start()
	c.userReportPeriodic.Start()
	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	if c.nodeInfoMonitorPeriodic != nil {
		err := c.nodeInfoMonitorPeriodic.Close()
		if err != nil {
			log.Panicf("node info periodic close failed: %s", err)
		}
	}

	if c.nodeInfoMonitorPeriodic != nil {
		err := c.userReportPeriodic.Close()
		if err != nil {
			log.Panicf("user report periodic close failed: %s", err)
		}
	}
	return nil
}

func (c *Controller) nodeInfoMonitor() (err error) {
	// First fetch Node Info
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		log.Print(err)
		return nil
	}				
			
	// Update User
	newUserInfo, err := c.apiClient.GetUserList()
	if err != nil {
		log.Print(err)
		return nil
	}
	
	var nodeInfoChanged bool = false

	c.removeRules(c.Tag, newUserInfo)		
	
	// If nodeInfo changed
	if !reflect.DeepEqual(c.nodeInfo, newNodeInfo) {
		oldtag := c.Tag
		// Remove old tag
		err := c.removeOldTag(oldtag)
		if err != nil {
			log.Print(err)
			return nil
		}
		
		if c.nodeInfo.NodeType == "Shadowsocks-Plugin"  {
			er := c.removeOldTag(fmt.Sprintf("dokodemo-door_%s", c.Tag))
			if er != nil {
				log.Print(er)
				return nil
			}
		}
        
		c.nodeInfo = newNodeInfo
		c.Tag = c.buildTag()
		
		nodeInfoChanged = true
					
		// Add new tag
		err = c.addNewTag(newNodeInfo)
		if err != nil {
			log.Panic(err)
			return err
		}
				
		// Remove Old limiter
		if err = c.DeleteInboundLimiter(oldtag); err != nil {
			log.Print(err)
			return nil
		}
	}
	
	// Remove Transit tag
	
	if c.Rtag == true {
		err := c.removeTransitTag(c.TransitTag, newUserInfo)
		if err != nil {
			return err
		}
	}
		
	c.Rtag = false
	
	// Add new Transit tag
	if c.nodeInfo.RelayNodeID > 0 {
		newTransitNodeInfo, err := c.apiClient.GetTransitNodeInfo()
		if err != nil {
			log.Print(err)
			return nil
		}
		c.transitnodeInfo = newTransitNodeInfo
		c.TransitTag = c.buildRTag()
		err = c.Transit(c.transitnodeInfo, newUserInfo)
		if err != nil {
			log.Panic(err)
			return err
		}
		c.Rtag = true			
	}
	
	// Check Rule
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			log.Printf("Get rule list filed: %s", err)
		} else if len(*ruleList) > 0 {
			if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
				log.Print(err)
			}
		}
	}

	// Check Cert
	if c.nodeInfo.EnableTLS && (c.config.CertConfig.CertMode == "dns" || c.config.CertConfig.CertMode == "http") {
		lego, err := legocmd.New()
		if err != nil {
			log.Print(err)
		}
		// Xray-core supports the OcspStapling certification hot renew
		_, _, err = lego.RenewCert(c.config.CertConfig.CertDomain, c.config.CertConfig.Email, c.config.CertConfig.CertMode, c.config.CertConfig.Provider, c.config.CertConfig.DNSEnv)
		if err != nil {
			log.Print(err)
		}
	}
	
	if nodeInfoChanged {
		err = c.addNewUser(newUserInfo, newNodeInfo)
		if err != nil {
			log.Print(err)
			return nil
		}
		// Add Limiter
		if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, newUserInfo); err != nil {
			log.Print(err)
			return nil
		}
	} else {
		deleted, added := compareUserList(c.userList, newUserInfo)
		if len(deleted) > 0 {
			deletedEmail := make([]string, len(deleted))
			for i, u := range deleted {
				deletedEmail[i] = fmt.Sprintf("%s|%s|%d", c.Tag, u.Email, u.UID)
			}
			err := c.removeUsers(deletedEmail, c.Tag)
			if err != nil {
				log.Print(err)
			}
			log.Printf("【NodeType：%s | NodeID: %d 】  Deleted %d Users", c.nodeInfo.NodeType,c.nodeInfo.NodeID, len(deleted))
		}
		if len(added) > 0 {
			err = c.addNewUser(&added, c.nodeInfo)
			if err != nil {
				log.Print(err)
			}
			// Update Limiter
			if err := c.UpdateInboundLimiter(c.Tag, &added); err != nil {
				log.Print(err)
			}
			//log.Printf("【NodeType：%s | NodeID: %d 】  Added %d Users", c.nodeInfo.NodeType,c.nodeInfo.NodeID, len(added))
		}
	}
	c.userList = newUserInfo
	
	return nil
}

func (c *Controller) removeOldTag(oldtag string) (err error) {
	err = c.removeInbound(oldtag)
	if err != nil {
		return err
	}
	err = c.removeOutbound(oldtag)
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) removeTransitTag(tag string, userInfo *[]api.UserInfo) (err error) {
	for _, user := range *userInfo {
		err = c.removeOutbound(fmt.Sprintf("Relay_%s|%d", tag,user.UID))
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) removeRules(tag string, userInfo *[]api.UserInfo){
	for _, user := range *userInfo {
		c.RemoveUserRoutingRule([]string{fmt.Sprintf("%s|%s|%d", tag, user.Email, user.UID)})			
	}	
}


func (c *Controller) addNewTag(newNodeInfo *api.NodeInfo) (err error) {
	if c.nodeInfo.NodeType == "Shadowsocks-Plugin" {
		return c.addInboundForSSPlugin(*newNodeInfo)
	} else {
		inboundConfig, err := InboundBuilder(c.config, newNodeInfo, c.Tag)
		if err != nil {
			return err
		}
		err = c.addInbound(inboundConfig)
		if err != nil {

			return err
		}	
		if c.nodeInfo.RelayNodeID <= 0 {
			outBoundConfig, err := OutboundBuilder(c.config, newNodeInfo, c.Tag)
			if err != nil {
				return err
			}
			err = c.addOutbound(outBoundConfig)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Controller) Transit(newTransitNodeInfo *api.TransitNodeInfo, userInfo *[]api.UserInfo) (err error) {
	if newTransitNodeInfo.NodeType != "Shadowsocks-Plugin" {
		for _, user := range *userInfo {			
			TransitConfig, err := TransitBuilder(c.config, newTransitNodeInfo, c.TransitTag, user.UUID, user.Email, user.Passwd, user.UID)
			if err != nil {
				return err
			}
			
			err = c.addOutbound(TransitConfig)
			if err != nil {
				return err
			}
			c.AddUserRoutingRule(c.TransitTag, []string{fmt.Sprintf("%s|%s|%d", c.Tag, user.Email, user.UID)})		
		}
	}
	return nil
}

func (c *Controller) addInboundForSSPlugin(newNodeInfo api.NodeInfo) (err error) {
	// Shadowsocks-Plugin require a seaperate inbound for other TransportProtocol likes: ws, grpc
	fakeNodeInfo := newNodeInfo
	fakeNodeInfo.TransportProtocol = "tcp"
	fakeNodeInfo.EnableTLS = false
	
	// Add a regular Shadowsocks inbound and outbound
	inboundConfig, err := InboundBuilder(c.config,  &fakeNodeInfo, c.Tag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err := OutboundBuilder(c.config, &fakeNodeInfo, c.Tag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {

		return err
	}

	// Add a inbound for upper streaming protocol
	fakeNodeInfo = newNodeInfo
	fakeNodeInfo.Port++
	fakeNodeInfo.NodeType = "dokodemo-door"
	dokodemoTag := fmt.Sprintf("dokodemo-door_%s", c.Tag)
	inboundConfig, err = InboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err = OutboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {

		return err
	}
	return nil
}

func (c *Controller) addNewUser(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo) (err error) {
	users := make([]*protocol.User, 0)
	if nodeInfo.NodeType == "Vmess" {
		users = buildVmessUser(c.Tag, userInfo, nodeInfo.AlterID)
	}else if nodeInfo.NodeType == "Vless" {
			users = buildVlessUser(c.Tag, userInfo)	
	} else if nodeInfo.NodeType == "Trojan" {
		users = buildTrojanUser(c.Tag, userInfo)
	} else if nodeInfo.NodeType == "Shadowsocks" {
		users = buildSSUser(c.Tag, userInfo, nodeInfo.CypherMethod)
	} else if nodeInfo.NodeType == "Shadowsocks-Plugin" {
		users = buildSSPluginUser(c.Tag, userInfo, nodeInfo.CypherMethod)	
	} else {
		return fmt.Errorf("Unsupported node type: %s", nodeInfo.NodeType)
	}
	//log.Printf("users: %v ", users)
	err = c.addUsers(users, c.Tag)
	if err != nil {
		return err
	}
	log.Printf("【NodeType：%s | NodeID: %d 】  Added %d New User(s)", c.nodeInfo.NodeType,c.nodeInfo.NodeID, len(*userInfo))
	
	return nil
}

func compareUserList(old, new *[]api.UserInfo) (deleted, added []api.UserInfo) {
	msrc := make(map[api.UserInfo]byte) 
	mall := make(map[api.UserInfo]byte)

	var set []api.UserInfo 

	for _, v := range *old {
		msrc[v] = 0
		mall[v] = 0
	}
	
	for _, v := range *new {
		l := len(mall)
		mall[v] = 1
		if l != len(mall) { 
			l = len(mall)
		} else { 
			set = append(set, v)
		}
	}
	
	
	for _, v := range set {
		delete(mall, v)
	}
	
	for v := range mall {
		_, exist := msrc[v]
		if exist {
			deleted = append(deleted, v)
		} else {
			added = append(added, v)
		}
	}

	return deleted, added
}

func (c *Controller) userInfoMonitor() (err error) {
	// Get server status
	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		log.Print(err)
	}
	err = c.apiClient.ReportNodeStatus(
		&api.NodeStatus{
			CPU:    CPU,
			Mem:    Mem,
			Disk:   Disk,
			Uptime: Uptime,
		})
	if err != nil {
		log.Print(err)
	}

	// Get User traffic
	var userTraffic []api.UserTraffic
	var upCounterList []stats.Counter
	var downCounterList []stats.Counter
	
	for _, user := range *c.userList {
	    up, down, upCounter, downCounter := c.getTraffic(fmt.Sprintf("%s|%s|%d", c.Tag, user.Email, user.UID))
		if up > 0 || down > 0 {
			userTraffic = append(userTraffic, api.UserTraffic{
				UID:      user.UID,
				Email:    user.Email,
				Upload:   up,
				Download: down})
				
			if upCounter != nil {
				upCounterList = append(upCounterList, upCounter)
			}
			if downCounter != nil {
				downCounterList = append(downCounterList, downCounter)
			}	
		}
	}
	
	if len(userTraffic) > 0 {
		var err error // Define an empty error
		if !c.config.DisableUploadTraffic {
			err = c.apiClient.ReportUserTraffic(&userTraffic)
		}
		// If report traffic error, not clear the traffic
		if err != nil {
			log.Print(err)
		} else {
			c.resetTraffic(&upCounterList, &downCounterList)
		}
	}

	// Report Online info
	if onlineDevice, err := c.GetOnlineDevice(c.Tag); err != nil {
		log.Print(err)
	} else if len(*onlineDevice) > 0 {
		if err = c.apiClient.ReportNodeOnlineUsers(onlineDevice); err != nil {
			log.Print(err)
		} else {
			log.Printf("Report %d Online IPs", len(*onlineDevice))
		}
	}
	
	// Report Illegal user
	if detectResult, err := c.GetDetectResult(c.Tag); err != nil {
		log.Print(err)
	} else if len(*detectResult) > 0 {
		if err = c.apiClient.ReportIllegal(detectResult); err != nil {
			log.Print(err)
		} else {
			log.Printf("【NodeType：%s | NodeID: %d 】  Report %d Activities matching rules", c.nodeInfo.NodeType,c.nodeInfo.NodeID, len(*detectResult))
		}

	}
	
	return nil
}

func (c *Controller) buildTag() string {
	return fmt.Sprintf("%s|%d|%d", c.nodeInfo.NodeType, c.nodeInfo.Port, c.nodeInfo.NodeID)
}


func (c *Controller) buildRTag() string {
	return fmt.Sprintf("%s_%d_%d", c.transitnodeInfo.NodeType, c.transitnodeInfo.Port, c.transitnodeInfo.NodeID)
}