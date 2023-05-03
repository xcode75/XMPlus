package controller

import (
	"github.com/xcode75/XMPlus/common/mylego"
)

type Config struct {
	UpdatePeriodic          int                              `mapstructure:"UpdatePeriodic"`
	CertConfig              *mylego.CertConfig               `mapstructure:"CertConfig"`
	RealityConfigs          *RealityConfig                   `mapstructure:"RealityConfigs"`
}

type RealityConfig struct {
	Show             bool     `mapstructure:"Show"`
	Dest             string   `mapstructure:"Dest"`
	Xver             uint64   `mapstructure:"Xver"`
	ServerNames      []string `mapstructure:"ServerNames"`
	PrivateKey       string   `mapstructure:"PrivateKey"`
	MinClientVer     string   `mapstructure:"MinClientVer"`
	MaxClientVer     string   `mapstructure:"MaxClientVer"`
	MaxTimeDiff      uint64   `mapstructure:"MaxTimeDiff"`
	ShortIds         []string `mapstructure:"ShortIds"`
}
