// Package config 配置信息定义
package config

import (
	"encoding/json"
	"strings"
)

type config struct {
	Timeout         int      `json:"timeout"`
	Aider           string   `json:"aider"`
	HTTPProxy       string   `json:"http_proxy"`
	PassList        []string `json:"pass_list"`
	ExtraPluginPath string   `json:"extra_plugin_path"`
}

// Debug 为True时打印过程日志
var Debug bool

// Config 全局配置信息
var Config config

func init() {
	Config.PassList = []string{
		"{user}", "{user}123", "admin", "123456", "",
	}
	Config.Timeout = 15
	Debug = false
}

// Set 设置配置信息
func Set(configJSON string) {
	json.Unmarshal([]byte(configJSON), &Config)
	if Config.Timeout == 0 {
		Config.Timeout = 15
	}
	if !strings.HasSuffix(Config.ExtraPluginPath, "/") {
		Config.ExtraPluginPath = Config.ExtraPluginPath + "/"
	}
}

// SetDebug 是否开启debug，即打印日志
func SetDebug(debug bool) {
	Debug = debug
}
