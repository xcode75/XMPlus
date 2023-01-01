package controller

import (
	"fmt"
	"strings"

	"github.com/xcode75/XMPlus/api"
	"github.com/xcode75/XMCore/common/protocol"
	"github.com/xcode75/XMCore/common/serial"
	"github.com/xcode75/XMCore/infra/conf"
	"github.com/xcode75/XMCore/proxy/shadowsocks"
	"github.com/xcode75/XMCore/proxy/trojan"
	"github.com/xcode75/XMCore/proxy/vless"
)

var AEADMethod = []shadowsocks.CipherType{shadowsocks.CipherType_AES_128_GCM, shadowsocks.CipherType_AES_256_GCM, shadowsocks.CipherType_CHACHA20_POLY1305}

func buildVmessUser(tag string, userInfo *[]api.UserInfo, serverAlterID uint16) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		vmessAccount := &conf.VMessAccount{
			ID:       user.UUID,
			AlterIds: uint16(serverAlterID),
			Security: "auto",
		}
		users[i] = &protocol.User{
			Level:   0,
			Email:   fmt.Sprintf("%s|%s|%d", tag, user.Email, user.UID), // Email: InboundTag|email|uid
			Account: serial.ToTypedMessage(vmessAccount.Build()),
		}
	}
	return users
}

func buildVlessUser(tag string, userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		vlessAccount := &vless.Account{
			Id:   user.UUID,
			Flow: "xtls-rprx-direct",
			Encryption: "none",
		}
		users[i] = &protocol.User{
			Level:   0,
			Email:   fmt.Sprintf("%s|%s|%d", tag, user.Email, user.UID),
			Account: serial.ToTypedMessage(vlessAccount),
		}
	}
	return users
}

func buildTrojanUser(tag string, userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		trojanAccount := &trojan.Account{
			Password: user.UUID,
			Flow:     "xtls-rprx-direct",
		}
		users[i] = &protocol.User{
			Level:   0,
			Email:   fmt.Sprintf("%s|%s|%d", tag, user.Email, user.UID),
			Account: serial.ToTypedMessage(trojanAccount),
		}
	}
	return users
}

func buildSSUser(tag string, userInfo *[]api.UserInfo, method string) (users []*protocol.User) {
	users = make([]*protocol.User, 0)
	cypherMethod := cipherFromString(method)
	for _, user := range *userInfo {
		ssAccount := &shadowsocks.Account{
			Password:   user.Passwd,
			CipherType: cypherMethod,
		}
		users = append(users, &protocol.User{
			Level:   0,
			Email:   fmt.Sprintf("%s|%s|%d", tag, user.Email, user.UID),
			Account: serial.ToTypedMessage(ssAccount),
		})
	}
	return users
}

func buildSSPluginUser(tag string, userInfo *[]api.UserInfo, method string) (users []*protocol.User) {
	users = make([]*protocol.User, 0)
	cypherMethod := cipherFromString(method)
	for _, user := range *userInfo {
		ssAccount := &shadowsocks.Account{
			Password:   user.Passwd,
			CipherType: cypherMethod,
		}
		users = append(users, &protocol.User{
			Level:   0,
			Email:   fmt.Sprintf("%s|%s|%d", tag, user.Email, user.UID),
			Account: serial.ToTypedMessage(ssAccount),
		})
	}
	return users
}


func cipherFromString(c string) shadowsocks.CipherType {
	switch strings.ToLower(c) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305
	case "none", "plain":
		return shadowsocks.CipherType_NONE
	default:
		return shadowsocks.CipherType_UNKNOWN
	}
}
