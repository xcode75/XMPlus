package controller

import (
	"github.com/xcode75/xcore/infra/conf"
	"github.com/xcode75/XMPlus/common/mylego"
)

type Config struct {
	UpdatePeriodic          int                              `mapstructure:"UpdatePeriodic"`
	CertConfig              *mylego.CertConfig               `mapstructure:"CertConfig"`
	DNSConfig               *conf.DNSConfig
}

