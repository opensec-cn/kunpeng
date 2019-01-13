package jsonplugin

import (
	"fmt"
	"github.com/opensec-cn/kunpeng/plugin"
	"encoding/json"
)

func init(){	
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
		var p plugin.JSONPlugin
		json.Unmarshal(pluginStr, &p)
		// fmt.Println(plugin)
		plugin.JSONPlugins[p.Target] = append(plugin.JSONPlugins[p.Target],p)
	}
}
