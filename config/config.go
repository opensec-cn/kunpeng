package config

import "encoding/json"


type config struct{
	Timeout int			`json:"timeout"`
	Aider string		`json:"aider"`
	HTTPProxy string	`json:"httpproxy"`
	PassList []string	`json:"passlist"`
}

// Config 
var Config config

func init(){
	Config.PassList = []string{
		"{user}", "{user}123", "admin", "123456", "",
	}
	Config.Timeout = 15
}

// Set set config
func Set(configJSON string){
	json.Unmarshal([]byte(configJSON), &Config)
}
