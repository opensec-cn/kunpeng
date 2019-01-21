// Package config 配置信息定义
package config

import "encoding/json"

type config struct {
	Timeout   int      `json:"timeout"`
	Aider     string   `json:"aider"`
	HTTPProxy string   `json:"httpproxy"`
	PassList  []string `json:"passlist"`
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
}

// SetDebug 是否开启debug，即打印日志
func SetDebug(debug bool) {
	Debug = debug
}
