package main

import "plugin"
import "fmt"
import "encoding/json"


type config struct{
	Timeout int			`json:"timeout"`
	Aider string		`json:"aider"`
	HTTPProxy string	`json:"httpproxy"`
	PassList []string	`json:"passlist"`
}

type Meta struct{
	System string `json:"system"`
	PathList []string `json:"pathlist"`
	FileList []string `json:"filelist"`
	PassList []string `json:"passlist"`
}

type TaskInfo struct {
	Type string `json:"type"`
	Netloc string `json:"netloc"`
	Target string `json:"target"`
	Meta Meta `json:"meta"`
}

type Greeter interface {
	Check(taskJSON string) ([]map[string]string)
	GetPlugins() []map[string]string
	SetConfig(configJSON string)
}


func main() {
	// 加载go plugin
	plug, err := plugin.Open("./kunpeng_go.so")
	if err != nil {
		fmt.Println(err)
		return
	}
	symGreeter, err := plug.Lookup("Greeter")
	if err != nil {
		fmt.Println(err)
		return
	}
	kunpeng, ok := symGreeter.(Greeter)
	if !ok {
		fmt.Println("unexpected type from module symbol")
		return
	}

	// 获取插件信息
	fmt.Println(kunpeng.GetPlugins())

	// 修改配置
	c := &config{
		Timeout: 15,
		Aider: "",
		HTTPProxy: "",
		PassList: []string{"ptest"},
	}
	configJSONBytes, _ := json.Marshal(c)
	kunpeng.SetConfig(string(configJSONBytes))

	// 扫描目标
	task := TaskInfo{
		Type: "service",
		Netloc: "192.168.0.105:3306",
		Target: "mysql",
		Meta : Meta{
			System : "",
			PathList: []string{},
			FileList: []string{},
			PassList: []string{"ttest"},
		},
	}
	task2 := TaskInfo{
		Type: "web",
		Netloc: "http://www.google.cn",
		Target: "web",
		Meta : Meta{
			System : "",
			PathList: []string{},
			FileList: []string{},
			PassList: []string{},
		},
	}
	jsonBytes, _ := json.Marshal(task)
	result:= kunpeng.Check(string(jsonBytes))
	fmt.Println(result)
	jsonBytes, _ = json.Marshal(task2)
	result= kunpeng.Check(string(jsonBytes))
	fmt.Println(result)
}

