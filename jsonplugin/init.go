package jsonplugin

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"vuldb/common"
	"encoding/json"
)
// JSONPlugins JSON插件集
var JSONPlugins map[string][]common.JSONPlugin

func init(){
	JSONPlugins = make(map[string][]common.JSONPlugin)	
	loadJSONPlugin()
}

func loadJSONPlugin(){
	f,_ := FS(false).Open("/json")
	fileList,err:= f.Readdir(1000)
	if err!= nil{
		fmt.Println(err.Error())
	}
	for _,v:= range fileList{
		fmt.Println(v.Name())
		pluginStr := FSMustByte(false,"/json/" + v.Name())
		var plugin common.JSONPlugin
		json.Unmarshal(pluginStr, &plugin)
		// fmt.Println(plugin)
		JSONPlugins[plugin.Target] = append(JSONPlugins[plugin.Target],plugin)
	}
}

// Check JSON插件漏洞检测
func Check(URL string, plugin common.JSONPlugin) (bool, common.PluginInfo) {
	var request *http.Request
	var result common.PluginInfo
	if plugin.Request.PostData != "" {
		request, _ = http.NewRequest("POST", URL+plugin.Request.Path, strings.NewReader(plugin.Request.PostData))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		request, _ = http.NewRequest("GET", URL+plugin.Request.Path, nil)
	}
	resp, err := common.RequestDo(request, true)
	// fmt.Println(resp.ResponseRaw)
	if err != nil {
		return false, result
	}
	switch plugin.Verify.Type {
	case "string":
		if strings.Contains(resp.ResponseRaw, plugin.Verify.Match) {
			result = plugin.Meta
			result.Request = resp.RequestRaw
			result.Response = resp.ResponseRaw
			fmt.Println(true, result)
			return true, result
		}
		break
	case "regex":
		if ok, _ := regexp.MatchString(plugin.Verify.Match, resp.ResponseRaw); ok {
			result = plugin.Meta
			result.Request = resp.RequestRaw
			result.Response = resp.ResponseRaw
			return true, result
		}
		break
	case "md5":
		if common.GetMd5(resp.Body) == plugin.Verify.Match {
			result = plugin.Meta
			result.Request = resp.RequestRaw
			result.Response = resp.ResponseRaw
			return true, result
		}
	}
	return false, result
}