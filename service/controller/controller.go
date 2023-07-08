package controller

import (
	"fmt"
	"log"
	"reflect"
	"time"
	"strings"

	"github.com/xcode75/xcore/common/protocol"
	"github.com/xcode75/xcore/common/task"
	"github.com/xcode75/xcore/core"
	"github.com/xcode75/xcore/features/inbound"
	"github.com/xcode75/xcore/features/outbound"
	"github.com/xcode75/xcore/features/routing"
	"github.com/xcode75/xcore/features/stats"
	"github.com/xcode75/xcore/app/router"
	C "github.com/sagernet/sing/common"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/xcode75/XMPlus/api"
	"github.com/xcode75/XMPlus/app/mydispatcher"
	"github.com/xcode75/XMPlus/common/mylego"
)

type Controller struct {
	server       *core.Instance
	config       *Config
	clientInfo   api.ClientInfo
	apiClient    api.API
	nodeInfo     *api.NodeInfo
	relaynodeInfo *api.RelayNodeInfo
	Tag          string
	RelayTag     string
	Relay        bool
	userList     *[]api.UserInfo
	tasks        []periodicTask
	ibm          inbound.Manager
	obm          outbound.Manager
	stm          stats.Manager
	dispatcher   *mydispatcher.DefaultDispatcher
	rdispatcher  *router.Router
	startAt      time.Time
}

type periodicTask struct {
	tag string
	*task.Periodic
}

// New return a Controller service with default parameters.
func New(server *core.Instance, api api.API, config *Config) *Controller {
	controller := &Controller{
		server:     server,
		config:     config,
		apiClient:  api,
		ibm:        server.GetFeature(inbound.ManagerType()).(inbound.Manager),
		obm:        server.GetFeature(outbound.ManagerType()).(outbound.Manager),
		stm:        server.GetFeature(stats.ManagerType()).(stats.Manager),
		dispatcher: server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher),
		rdispatcher: server.GetFeature(routing.RouterType()).(*router.Router),
		startAt:    time.Now(),
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
	c.Tag = c.buildNodeTag()

	// Update user
	userInfo, err := c.apiClient.GetUserList()
	if err != nil {
		return err
	}

	// sync controller userList
	c.userList = userInfo
	
	c.Relay = false
	
	// Add new Relay	tag
	if c.nodeInfo.Relay {
		newRelayNodeInfo, err := c.apiClient.GetRelayNodeInfo()
		if err != nil {
			log.Panic(err)
			return nil
		}	
		c.relaynodeInfo = newRelayNodeInfo
		c.RelayTag = c.buildRNodeTag()
		
		log.Printf("%s Taking a Detour Route [%s] For Users", c.logPrefix(), c.RelayTag)
		err = c.addNewRelayTag(newRelayNodeInfo, userInfo)
		if err != nil {
			log.Panic(err)
			return err
		}
		c.Relay = true
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

	if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
		log.Printf("Get rule list filed: %s", err)
	} else if len(*ruleList) > 0 {
		if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
			log.Print(err)
		}
	}

	// Add periodic tasks
	c.tasks = append(c.tasks,
		periodicTask{
			tag: "Node",
			Periodic: &task.Periodic{
				Interval: time.Duration(60) * time.Second,
				Execute:  c.nodeInfoMonitor,
			}},
		periodicTask{
			tag: "User",
			Periodic: &task.Periodic{
				Interval: time.Duration(60) * time.Second,
				Execute:  c.userInfoMonitor,
			}},
	)

	// Check cert service in need
	if c.nodeInfo.TLSType == "tls"  && c.nodeInfo.CertMode != "none" {
		c.tasks = append(c.tasks, periodicTask{
			tag: "Cert",
			Periodic: &task.Periodic{
				Interval: time.Duration(60) * time.Second * 60,
				Execute:  c.certMonitor,
			}})
	}

	// Start periodic tasks
	for i := range c.tasks {
		log.Printf("%s task scheduler for %s started", c.logPrefix(), c.tasks[i].tag)
		go c.tasks[i].Start()
	}

	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	for i := range c.tasks {
		if c.tasks[i].Periodic != nil {
			if err := c.tasks[i].Periodic.Close(); err != nil {
				log.Panicf("%s Task Scheduler for  %s failed to close: %s", c.logPrefix(), c.tasks[i].tag, err)
			}
		}
	}

	return nil
}

func (c *Controller) nodeInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(60)*time.Second {
		return nil
	}

	var nodeInfoChanged = true
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			nodeInfoChanged = false
			newNodeInfo = c.nodeInfo
		} else {
			log.Print(err)
			return nil
		}
	}	

	// Update User
	var usersChanged = true
	
	newUserInfo, err := c.apiClient.GetUserList()
	if err != nil {
		if err.Error() == api.UserNotModified {
			usersChanged = false
			newUserInfo = c.userList
		} else {
			log.Print(err)
			return nil
		}
	}

	var updateRelay = false	
	
	if usersChanged {
		updateRelay = true
		c.removeRules(c.Tag, c.userList)
	}
	
	
	if nodeInfoChanged {
		if !reflect.DeepEqual(c.nodeInfo, newNodeInfo) {
			// Remove old tag
			oldTag := c.Tag
			err := c.removeOldTag(oldTag)
			if err != nil {
				log.Print(err)
				return nil
			}
			if c.nodeInfo.NodeType == "Shadowsocks-Plugin" {
				err = c.removeOldTag(fmt.Sprintf("dokodemo-door_%s+1", c.Tag))
			}
			if err != nil {
				log.Print(err)
				return nil
			}
			updateRelay = true
			
			// Add new tag
			c.nodeInfo = newNodeInfo
			c.Tag = c.buildNodeTag()
			err = c.addNewTag(newNodeInfo)
			if err != nil {
				log.Print(err)
				return nil
			}
			nodeInfoChanged = true
			// Remove Old limiter
			if err = c.DeleteInboundLimiter(oldTag); err != nil {
				log.Print(err)
				return nil
			}
		} else {
			nodeInfoChanged = false
		}
	}
	
	// Remove relay tag
	if c.Relay && updateRelay {
		err := c.removeRelayTag(c.RelayTag, c.userList)
		if err != nil {
			return err
		}
		c.Relay = false
	}
	
	// Update new Relay tag
	if c.nodeInfo.Relay && updateRelay {
		newRelayNodeInfo, err := c.apiClient.GetRelayNodeInfo()
		if err != nil {
			log.Panic(err)
			return nil
		}	
		c.relaynodeInfo = newRelayNodeInfo
		c.RelayTag = c.buildRNodeTag()
		
		log.Printf("%s Reload Detour Route [%s] For Users", c.logPrefix(), c.RelayTag)
		
		err = c.addNewRelayTag(newRelayNodeInfo, newUserInfo)
		if err != nil {
			log.Panic(err)
			return err
		}
		c.Relay = true
	}	
	
	// Check Rule	
	if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
		if err.Error() != api.RuleNotModified {
			log.Printf("Get rule list filed: %s", err)
		}
	} else if len(*ruleList) > 0 {
		if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
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
		var deleted, added []api.UserInfo
		if usersChanged {
			deleted, added = compareUserList(c.userList, newUserInfo)
			if len(deleted) > 0 {
				deletedEmail := make([]string, len(deleted))
				for i, u := range deleted {
					deletedEmail[i] = fmt.Sprintf("%s|%s|%d", c.Tag, u.Email, u.UID)
				}
				err := c.removeUsers(deletedEmail, c.Tag)
				if err != nil {
					log.Print(err)
				}
				log.Printf("%s %d Users Deleted", c.logPrefix(), len(deleted))
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
			}
		}	
	}
	c.userList = newUserInfo
	return nil
}

func (c *Controller) removeOldTag(oldTag string) (err error) {
	err = c.removeInbound(oldTag)
	if err != nil {
		return err
	}
	err = c.removeOutbound(oldTag)
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) addNewTag(newNodeInfo *api.NodeInfo) (err error) {
	if newNodeInfo.NodeType != "Shadowsocks-Plugin" {
		inboundConfig, err := InboundBuilder(c.config, newNodeInfo, c.Tag)
		if err != nil {
			return err
		}
		err = c.addInbound(inboundConfig)
		if err != nil {

			return err
		}
		if !c.nodeInfo.Relay {
			outBoundConfig, err := OutboundBuilder(c.config, newNodeInfo, c.Tag)
			if err != nil {

				return err
			}
			err = c.addOutbound(outBoundConfig)
			if err != nil {

				return err
			}
		}

	} else {
		return c.addInboundForSSPlugin(*newNodeInfo)
	}
	return nil
}

func (c *Controller) removeRelayTag(tag string, userInfo *[]api.UserInfo) (err error) {
	for _, user := range *userInfo {
		err = c.removeOutbound(fmt.Sprintf("%s_%d", tag, user.UID))
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) removeRules(tag string, userInfo *[]api.UserInfo){
	for _, user := range *userInfo {
		c.RemoveUsersRule([]string{c.buildUserTag(&user)})			
	}	
}

func (c *Controller) addNewRelayTag(newRelayNodeInfo *api.RelayNodeInfo, userInfo *[]api.UserInfo) (err error) {
	if newRelayNodeInfo.NodeType != "Shadowsocks-Plugin" {
		for _, user := range *userInfo {
			var Key string			
			if C.Contains(shadowaead_2022.List, strings.ToLower(newRelayNodeInfo.CypherMethod)) {
				userKey, err := c.checkShadowsocksPassword(user.Passwd, newRelayNodeInfo.CypherMethod)
				if err != nil {
					newError(fmt.Errorf("[UID: %d] %s", user.UUID, err)).AtError().WriteToLog()
					continue
				}
				Key = fmt.Sprintf("%s:%s", newRelayNodeInfo.ServerKey, userKey)
			} else {
				Key = user.Passwd
			}
			RelayTagConfig, err := OutboundRelayBuilder(c.config, newRelayNodeInfo, c.RelayTag, user.UUID, user.Email, Key, user.UID)
			if err != nil {
				return err
			}
			
			err = c.addOutbound(RelayTagConfig)
			if err != nil {
				return err
			}
			c.AddUsersRule(fmt.Sprintf("%s_%d", c.RelayTag, user.UID), []string{c.buildUserTag(&user)})		
		}
	}
	return nil
}

func (c *Controller) addInboundForSSPlugin(newNodeInfo api.NodeInfo) (err error) {
	// Shadowsocks-Plugin require a separate inbound for other TransportProtocol likes: ws, grpc
	fakeNodeInfo := newNodeInfo
	fakeNodeInfo.TransportProtocol = "tcp"
	fakeNodeInfo.EnableTLS = false
	// Add a regular Shadowsocks inbound and outbound
	inboundConfig, err := InboundBuilder(c.config, &fakeNodeInfo, c.Tag)
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
	// Add an inbound for upper streaming protocol
	fakeNodeInfo = newNodeInfo
	fakeNodeInfo.Port++
	fakeNodeInfo.NodeType = "dokodemo-door"
	dokodemoTag := fmt.Sprintf("dokodemo-door_%s+1", c.Tag)
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
	switch nodeInfo.NodeType {
	case "Vless":
		users = c.buildVlessUser(userInfo, nodeInfo.Flow)
	case "Vmess":
		users = c.buildVmessUser(userInfo)	
	case "Trojan":
		users = c.buildTrojanUser(userInfo)
	case "Shadowsocks":
		users = c.buildSSUser(userInfo, nodeInfo.CypherMethod)
	case "Shadowsocks-Plugin":
		users = c.buildSSPluginUser(userInfo, nodeInfo.CypherMethod)	
	default:
		return fmt.Errorf("unsupported node type: %s", nodeInfo.NodeType)
	}

	err = c.addUsers(users, c.Tag)
	if err != nil {
		return err
	}
	log.Printf("%s %d New Users Added", c.logPrefix(), len(*userInfo))
	return nil
}

func compareUserList(old, new *[]api.UserInfo) (deleted, added []api.UserInfo) {
	mSrc := make(map[api.UserInfo]byte) 
	mAll := make(map[api.UserInfo]byte) 

	var set []api.UserInfo 

	for _, v := range *old {
		mSrc[v] = 0
		mAll[v] = 0
	}

	for _, v := range *new {
		l := len(mAll)
		mAll[v] = 1
		if l != len(mAll) {
			l = len(mAll)
		} else { 
			set = append(set, v)
		}
	}
	
	for _, v := range set {
		delete(mAll, v)
	}
	
	for v := range mAll {
		_, exist := mSrc[v]
		if exist {
			deleted = append(deleted, v)
		} else {
			added = append(added, v)
		}
	}

	return deleted, added
}

func (c *Controller) userInfoMonitor() (err error) {

	// Get User traffic
	var userTraffic []api.UserTraffic
	var upCounterList []stats.Counter
	var downCounterList []stats.Counter

	for _, user := range *c.userList {
		up, down, upCounter, downCounter := c.getTraffic(c.buildUserTag(&user))
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

		err = c.apiClient.ReportUserTraffic(&userTraffic)
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
			log.Printf("%s Report %d online IPs", c.logPrefix(), len(*onlineDevice))
		}
	}
	
	if detectResult, err := c.GetDetectResult(c.Tag); err != nil {
		log.Print(err)
	} else if len(*detectResult) > 0 {
		log.Printf("%s blocked %d access by detection rules", c.logPrefix(), len(*detectResult))
	}
	
	return nil
}

func (c *Controller) buildNodeTag() string {
	return fmt.Sprintf("%s_%d_%d", c.nodeInfo.NodeType, c.nodeInfo.Port, c.nodeInfo.NodeID)
}

func (c *Controller) buildRNodeTag() string {
	return fmt.Sprintf("Relay_%d_%s_%d_%d", c.nodeInfo.NodeID, c.relaynodeInfo.NodeType, c.relaynodeInfo.Port, c.relaynodeInfo.NodeID)
}

func (c *Controller) logPrefix() string {
	return fmt.Sprintf("[%s] %s(NodeID=%d)", c.clientInfo.APIHost, c.nodeInfo.NodeType, c.nodeInfo.NodeID)
}

// Check Cert
func (c *Controller) certMonitor() error {
	if c.nodeInfo.TLSType == "tls"  {
		switch c.nodeInfo.CertMode {
		case "dns", "http":
			lego, err := mylego.New(c.config.CertConfig)
			if err != nil {
				log.Print(err)
			}
			_, _, _, err = lego.RenewCert(c.nodeInfo.CertMode, c.nodeInfo.CertDomain)
			if err != nil {
				log.Print(err)
			}
		}
	}
	return nil
}
