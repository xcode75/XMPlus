package controller

import (
	"context"
	"fmt"

	"github.com/xcode75/XMPlus/api"
	"github.com/xcode75/XMPlus/app/mydispatcher"
	"github.com/xcode75/XMCore/common/protocol"
	"github.com/xcode75/XMCore/core"
	"github.com/xcode75/XMCore/features/inbound"
	"github.com/xcode75/XMCore/features/outbound"
	"github.com/xcode75/XMCore/features/routing"
	"github.com/xcode75/XMCore/app/router"
	"github.com/xcode75/XMCore/features/stats"
	"github.com/xcode75/XMCore/proxy"
)

func (c *Controller) removeInbound(tag string) error {
	inboundManager := c.server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	err := inboundManager.RemoveHandler(context.Background(), tag)
	return err
}

func (c *Controller) removeOutbound(tag string) error {
	outboundManager := c.server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	err := outboundManager.RemoveHandler(context.Background(), tag)
	return err
}

func (c *Controller) addInbound(config *core.InboundHandlerConfig) error {
	inboundManager := c.server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	rawHandler, err := core.CreateObject(c.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	if err := inboundManager.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (c *Controller) addOutbound(config *core.OutboundHandlerConfig) error {
	outboundManager := c.server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	rawHandler, err := core.CreateObject(c.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(outbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	if err := outboundManager.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (c *Controller) addUsers(users []*protocol.User, tag string) error {
	inboundManager := c.server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	handler, err := inboundManager.GetHandler(context.Background(), tag)
	if err != nil {
		return fmt.Errorf("No such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.UserManager", err)
	}
	for _, item := range users {
		mUser, err := item.ToMemoryUser()
		if err != nil {
			return err
		}
		err = userManager.AddUser(context.Background(), mUser)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) removeUsers(users []string, tag string) error {
	inboundManager := c.server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	handler, err := inboundManager.GetHandler(context.Background(), tag)
	if err != nil {
		return fmt.Errorf("No such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.UserManager", err)
	}
	for _, email := range users {
		err = userManager.RemoveUser(context.Background(), email)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) getTraffic(email string) (up int64, down int64, upCounter stats.Counter, downCounter stats.Counter) {
	upName := "user>>>" + email + ">>>traffic>>>uplink"
	downName := "user>>>" + email + ">>>traffic>>>downlink"
	upCounter = c.stm.GetCounter(upName)
	downCounter = c.stm.GetCounter(downName)
	if upCounter != nil && upCounter.Value() != 0 {
		up = upCounter.Value()
	} else {
		upCounter = nil
	}
	if downCounter != nil && downCounter.Value() != 0 {
		down = downCounter.Value()
	} else {
		downCounter = nil
	}
	return up, down, upCounter, downCounter
}

func (c *Controller) resetTraffic(upCounterList *[]stats.Counter, downCounterList *[]stats.Counter) {
	for _, upCounter := range *upCounterList {
		upCounter.Set(0)
	}
	for _, downCounter := range *downCounterList {
		downCounter.Set(0)
	}
}

func (c *Controller) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.UserInfo) error {
	dispather := c.server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher)
	err := dispather.Limiter.AddInboundLimiter(tag, nodeSpeedLimit, userList)
	return err
}

func (c *Controller) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo) error {
	dispather := c.server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher)
	err := dispather.Limiter.UpdateInboundLimiter(tag, updatedUserList)
	return err
}

func (c *Controller) DeleteInboundLimiter(tag string) error {
	dispather := c.server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher)
	err := dispather.Limiter.DeleteInboundLimiter(tag)
	return err
}

func (c *Controller) GetOnlineDevice(tag string) (*[]api.OnlineUser, error) {
	dispather := c.server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher)
	return dispather.Limiter.GetOnlineDevice(tag)
}

func (c *Controller) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	dispather := c.server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher)
	err := dispather.RuleManager.UpdateRule(tag, newRuleList)
	return err
}

func (c *Controller) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	dispather := c.server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher)
	return dispather.RuleManager.GetDetectResult(tag)
}

func (c *Controller) AddUserRoutingRule(tag string, email []string) {
	dispather := c.server.GetFeature(routing.RouterType()).(*router.Router)
	dispather.AddUser(tag, email)
}

func (c *Controller) RemoveUserRoutingRule(email []string)  {
	dispather := c.server.GetFeature(routing.RouterType()).(*router.Router)
	dispather.RemoveUser(email)
	return
}