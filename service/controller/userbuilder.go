package controller

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	"github.com/xcode75/xcore/common/protocol"
	"github.com/xcode75/xcore/common/serial"
	"github.com/xcode75/xcore/infra/conf"
	"github.com/xcode75/xcore/proxy/shadowsocks"
	"github.com/xcode75/xcore/proxy/shadowsocks_2022"
	"github.com/xcode75/xcore/proxy/trojan"
	"github.com/xcode75/xcore/proxy/vless"
	"github.com/xcode75/XMPlus/api"
)

var AEADMethod = map[shadowsocks.CipherType]uint8{
	shadowsocks.CipherType_AES_128_GCM:        0,
	shadowsocks.CipherType_AES_256_GCM:        0,
	shadowsocks.CipherType_CHACHA20_POLY1305:  0,
	shadowsocks.CipherType_XCHACHA20_POLY1305: 0,
}

func (c *Controller) buildVmessUser(userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		vmessAccount := &conf.VMessAccount{
			ID:       user.UUID,
			Security: "auto",
		}
		users[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&user), // Email: InboundTag|email|uid
			Account: serial.ToTypedMessage(vmessAccount.Build()),
		}
	}
	return users
}

func (c *Controller) buildVlessUser(userInfo *[]api.UserInfo, flow string) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		vlessAccount := &vless.Account{
			Id:   user.UUID,
			Flow: flow,
		}
		users[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&user),
			Account: serial.ToTypedMessage(vlessAccount),
		}
	}
	return users
}

func (c *Controller) buildTrojanUser(userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		trojanAccount := &trojan.Account{
			Password: user.UUID,
		}
		users[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&user),
			Account: serial.ToTypedMessage(trojanAccount),
		}
	}
	return users
}

func (c *Controller) buildSSUser(userInfo *[]api.UserInfo, method string) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		if C.Contains(shadowaead_2022.List, strings.ToLower(method)) {
			e := c.buildUserTag(&user)
			userKey, err := c.checkShadowsocksPassword(user.Passwd, method)
			if err != nil {
				newError(fmt.Errorf("[UID: %d] %s", user.UID, err)).AtError().WriteToLog()
				continue
			}
			users[i] = &protocol.User{
				Level: 0,
				Email: e,
				Account: serial.ToTypedMessage(&shadowsocks_2022.User{
					Key:   userKey,
					Email: e,
					Level: 0,
				}),
			}
		} else {
			users[i] = &protocol.User{
				Level: 0,
				Email: c.buildUserTag(&user),
				Account: serial.ToTypedMessage(&shadowsocks.Account{
					Password:   user.Passwd,
					CipherType: cipherFromString(method),
				}),
			}
		}
	}
	return users
}

func (c *Controller) buildSSPluginUser(userInfo *[]api.UserInfo, method string) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		if C.Contains(shadowaead_2022.List, strings.ToLower(method)) {
			e := c.buildUserTag(&user)
			userKey, err := c.checkShadowsocksPassword(user.Passwd, method)
			if err != nil {
				newError(fmt.Errorf("[UID: %d] %s", user.UID, err)).AtError().WriteToLog()
				continue
			}
			users[i] = &protocol.User{
				Level: 0,
				Email: e,
				Account: serial.ToTypedMessage(&shadowsocks_2022.User{
					Key:   userKey,
					Email: e,
					Level: 0,
				}),
			}
		} else {
			// Check if the cypher method is AEAD
			cypherMethod := cipherFromString(method)
			if _, ok := AEADMethod[cypherMethod]; ok {
				users[i] = &protocol.User{
					Level: 0,
					Email: c.buildUserTag(&user),
					Account: serial.ToTypedMessage(&shadowsocks.Account{
						Password:   user.Passwd,
						CipherType: cypherMethod,
					}),
				}
			}
		}
	}
	return users
}

func (c *Controller) buildUserTag(user *api.UserInfo) string {
	return fmt.Sprintf("%s|%s|%d", c.Tag, user.Email, user.UID)
}

func (c *Controller) checkShadowsocksPassword(password string, method string) (string, error) {
	var userKey string
	if len(password) < 16 {
		return "", fmt.Errorf("shadowsocks2022 key's length must be greater than 16")
	}
	if method == "2022-blake3-aes-128-gcm" {
		userKey = password[:16]
	} else {
		if len(password) < 32 {
			return "", fmt.Errorf("shadowsocks2022 key's length must be greater than 32")
		}
		userKey = password[:32]
	}
	return base64.StdEncoding.EncodeToString([]byte(userKey)), nil
}