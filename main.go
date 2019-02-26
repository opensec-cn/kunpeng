package main

import "C" // required
import (
	"encoding/json"
	"github.com/opensec-cn/kunpeng/config"
	"github.com/opensec-cn/kunpeng/plugin"
	_ "github.com/opensec-cn/kunpeng/plugin/go"
	_ "github.com/opensec-cn/kunpeng/plugin/json"
	"github.com/opensec-cn/kunpeng/util"
	"github.com/opensec-cn/kunpeng/web"
)

var VERSION string

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

func (g greeting) ShowLog() {
	config.SetDebug(true)
}

func (g greeting) GetVersion() string {
	return VERSION
}

//export StartWebServer
func StartWebServer(bindAddr *C.char) {
	go web.StartServer(C.GoString(bindAddr))
}

//export Check
func Check(task *C.char) *C.char {
	util.Logger.Info(C.GoString(task))
	var m plugin.Task
	err := json.Unmarshal([]byte(C.GoString(task)), &m)
	if err != nil {
		util.Logger.Error(err.Error())
		return C.CString("[]")
	}
	util.Logger.Info(m)
	result := plugin.Scan(m)
	if len(result) == 0 {
		return C.CString("[]")
	}
	b, err := json.Marshal(result)
	if err != nil {
		util.Logger.Error(err.Error())
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
		util.Logger.Error(err.Error())
		return C.CString("[]")
	}
	result = string(b)
	return C.CString(result)
}

//export SetConfig
func SetConfig(configJSON *C.char) {
	config.Set(C.GoString(configJSON))
}

//export ShowLog
func ShowLog() {
	config.SetDebug(true)
}

//export GetVersion
func GetVersion() *C.char {
	return C.CString(VERSION)
}

var Greeter greeting

func main() {}
