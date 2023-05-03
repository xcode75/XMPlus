package panel

import "github.com/xcode75/XMPlus/service/controller"

func getDefaultLogConfig() *LogConfig {
	return &LogConfig{
		Level:      "none",
		AccessPath: "",
		ErrorPath:  "",
	}
}

func getDefaultConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		Handshake:    4,
		ConnIdle:     30,
		UplinkOnly:   2,
		DownlinkOnly: 4,
		BufferSize:   64,
	}
}

func getDefaultControllerConfig() *controller.Config {
	return &controller.Config{}
}
