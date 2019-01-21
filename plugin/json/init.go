package jsonplugin

import (
	"encoding/json"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

func init() {
	loadJSONPlugin()
}

func loadJSONPlugin() {
	f, _ := FS(false).Open("/json")
	fileList, err := f.Readdir(1000)
	if err != nil {
		util.Logger.Error(err.Error())
		return
	}
	for _, v := range fileList {
		.Logger.Info("初始化插件", v.Name())
		pluginStr := FSMustByte(false, "/json/"+v.Name())
		var p plugin.JSONPlugin
		json.Unmarshal(pluginStr, &p)
		plugin.JSONPlugins[p.Target] = append(plugin.JSONPlugins[p.Target], p)
	}
}
