// To implement an api , one needs to implement the interface below.

package api

// API is the interface for different panel's api.
type API interface {
	GetNodeInfo() (nodeInfo *NodeInfo, err error)
	GetRelayNodeInfo() (nodeInfo *RelayNodeInfo, err error)
	GetUserList() (userList *[]UserInfo, err error)
	ReportNodeOnlineUsers(onlineUser *[]OnlineUser) (err error)
	ReportUserTraffic(userTraffic *[]UserTraffic) (err error)
	GetNodeRule() (ruleList *[]DetectRule, err error)
	Describe() ClientInfo
	Debug()
}
