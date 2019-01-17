package config

import "encoding/json"

type config struct {
	Timeout   int      `json:"timeout"`
	Aider     string   `json:"aider"`
	HTTPProxy string   `json:"httpproxy"`
	PassList  []string `json:"passlist"`
}

// Config 全局配置信息
var Config config

func init() {
	Config.PassList = []string{
		"{user}", "{user}123", "admin", "123456", "",
	}
	Config.Timeout = 15
}

// Set 设置配置信息
func Set(configJSON string) {
	json.Unmarshal([]byte(configJSON), &Config)
	if Config.Timeout == 0 {
		Config.Timeout = 15
	}
}
