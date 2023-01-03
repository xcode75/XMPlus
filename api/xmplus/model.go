package xmplus

import "encoding/json"


type User struct {
	Id         int    `json:"id"`
	Uuid       string `json:"uuid"`
	Email      string `json:"email"`
	Speedlimit int    `json:"speedlimit"`
	Iplimit    int    `json:"iplimit"`
	Ipcount    int    `json:"ipcount"`
}

// Response is the common response
type Response struct {
	Ret  uint            `json:"ret"`
	Data json.RawMessage `json:"data"`
}

// PostData is the data structure of post data
type PostData struct {
	Data interface{} `json:"data"`
}

// SystemLoad is the data structure of systemload
type SystemLoad struct {
	Uptime string `json:"uptime"`
	Load   string `json:"load"`
}

// OnlineUser is the data structure of online user
type OnlineUser struct {
	UID int    `json:"user_id"`
	IP  string `json:"ip"`
}

// UserTraffic is the data structure of traffic
type UserTraffic struct {
	UID      int   `json:"user_id"`
	Upload   int64 `json:"u"`
	Download int64 `json:"d"`
}

type IllegalItem struct {
	ID  int `json:"list_id"`
	UID int `json:"user_id"`
}
