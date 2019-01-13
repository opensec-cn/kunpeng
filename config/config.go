package config


type config struct{
	Aider string
	HTTPProxy string
	PassList []string
}

// Config 
var Config config

func init(){
	Config.PassList = []string{
		"{user}", "{user}123", "admin", "123456", "",
	}
}
