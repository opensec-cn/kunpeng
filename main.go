package main

import "C" // required
import (
	"fmt"
	"github.com/opensec-cn/kunpeng/config"
	"github.com/opensec-cn/kunpeng/plugin"
	_ "github.com/opensec-cn/kunpeng/plugin/go"
	"github.com/opensec-cn/kunpeng/web"
	"encoding/json"
)
//go:generate esc -include='\.json$' -o plugin/json/JSONPlugin.go -pkg jsonplugin plugin/json/

type greeting string

func (g greeting) Check(taskJSON string) []map[string]interface{} {
	var task plugin.Task
	json.Unmarshal([]byte(taskJSON), &task)
	return plugin.Scan(task)
}

func (g greeting) GetPlugins() []map[string]interface{} {
	return plugin.GetPlugins()
}

func (g greeting) SetConfig(configJSON string) {
	config.Set(configJSON)
}

//export StartWebServer
func StartWebServer() {
	go web.StartServer()
}

//export Check
func Check(task *C.char) *C.char {
	fmt.Println(C.GoString(task))
	var m plugin.Task
    err := json.Unmarshal([]byte(C.GoString(task)), &m)
    if err != nil {
		fmt.Println(err.Error())
        return C.CString("[]")
	}
	fmt.Println(m)
	result := plugin.Scan(m)
	if len(result) == 0{
		return C.CString("[]")
	}
	b, err := json.Marshal(result)
    if err != nil {
		fmt.Println(err.Error())
        return C.CString("[]")
	}
	return C.CString(string(b))
}

//export GetPlugins
func GetPlugins() *C.char {
	var result string
	plugins := plugin.GetPlugins()
	b, err := json.Marshal(plugins)
    if err != nil {
        fmt.Println("json.Marshal failed:", err)
        return C.CString("[]")
	}
	result = string(b)
	return C.CString(result)
}

//export SetConfig
func SetConfig(configJSON *C.char) {
	config.Set(C.GoString(configJSON))
}

var Greeter greeting

func main() {}
