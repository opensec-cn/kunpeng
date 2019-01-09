package main

import "C" // required
import (
	"fmt"
	"crypto/tls"
	"net/http"
	"net/url"
	"github.com/opensec-cn/kunpeng/util"
	"github.com/opensec-cn/kunpeng/plugin"
	_ "github.com/opensec-cn/kunpeng/goplugin"
	"github.com/opensec-cn/kunpeng/web"
	"encoding/json"
	// "fmt"
)
//go:generate esc -o jsonplugin/JSONPlugin.go -pkg jsonplugin json

type greeting string

func (g greeting) Check(taskJSON string) (bool, []map[string]string) {
	var task plugin.TaskInfo
	json.Unmarshal([]byte(taskJSON), &task)
	return plugin.Scan(task)
}

func (g greeting) GetPlugins() []map[string]string {
	return plugin.GetPlugins()
}

func (g greeting) SetProxy(URL string) {
	if URL == "" {
		util.Client.Transport = nil
	} else {
		proxy := func(_ *http.Request) (*url.URL, error) {
			return url.Parse(URL)
		}
		transport := &http.Transport{
			Proxy:           proxy,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		util.Client.Transport = transport
	}
}

func (g greeting) SetAider(URL string) {
	plugin.Config.Aider = URL
}

func (g greeting) SetPassList(dic []string) {
	plugin.Config.PassList = dic
}

//export StartWebServer
func StartWebServer() {
	web.StartServer()
}

//export Check
func Check(task *C.char) *C.char {
	fmt.Println(C.GoString(task))
	var m plugin.TaskInfo
    err := json.Unmarshal([]byte(C.GoString(task)), &m)
    if err != nil {
		fmt.Println(err.Error())
        return C.CString("[]")
	}
	fmt.Println(m)
	ok, result := plugin.Scan(m)
	if ok == false || len(result) == 0{
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
        // fmt.Println("json.Marshal failed:", err)
        return C.CString("[]")
	}
	result = string(b)
	return C.CString(result)
}

var Greeter greeting

func main() {}
