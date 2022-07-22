package api

type API interface {
	GetNodeInfo() (nodeInfo *NodeInfo, err error)
	GetTransitNodeInfo() (transitnodeinfo *TransitNodeInfo, err error)
	GetUserList() (userList *[]UserInfo, err error)
	ReportNodeStatus(nodeStatus *NodeStatus) (err error)
	ReportNodeOnlineUsers(onlineUser *[]OnlineUser) (err error)
	ReportUserTraffic(userTraffic *[]UserTraffic) (err error)
	Describe() ClientInfo
	GetNodeRule() (ruleList *[]DetectRule, err error)
	ReportIllegal(detectResultList *[]DetectResult) (err error)
	Debug()
}
