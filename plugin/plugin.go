package plugin

import (
	"strings"
	"fmt"
	"vuldb/jsonplugin"
	"vuldb/common"
)

// Plugins 漏洞插件库
var Plugins map[string][]Plugin

// TaskInfo 任务结构
type TaskInfo struct {
	Type string `json:"type"`
	Netloc string `json:"netloc"`
	Target string `json:"target"`
	System string `json:"system"`
	PathList []string `json:"pathList"`
	FileList []string `json:"fileList"`
}


// TaskMeta 任务额外信息
type TaskMeta struct{
	System		string
	PathList	[]string
	FileList	[]string
}

// Plugin 插件接口
type Plugin interface {
	Init() common.PluginInfo
	Check(netloc string, meta TaskMeta) bool
	GetResult() []common.PluginInfo
}

func init() {
	Plugins = make(map[string][]Plugin)
}

// Regist 注册插件
func Regist(target string, plugin Plugin) {
	Plugins[target] = append(Plugins[target], plugin)
}

// Scan 开始插件扫描
func Scan(task TaskInfo) (ok bool, result []map[string]string) {
	// GO插件
	for n, pluginList := range Plugins {
		if strings.Contains(strings.ToLower(task.Target),strings.ToLower(n)) || task.Target == "all" {
			fmt.Printf("启动插件集 %s\n", n)
			for _, plugin := range pluginList {
				plugin.Init()
				if !plugin.Check(task.Netloc, TaskMeta{task.System,task.PathList,task.FileList}) {
					continue
				}
				ok = true
				for _, res := range plugin.GetResult() {
					fmt.Println("true:", res.Name)
					result = append(result, common.Struct2Map(res))
				}
			}
		}
	}
	if task.Type == "service" {
		return ok, result
	}
	// JSON插件
	for target, pluginList := range jsonplugin.JSONPlugins {
		if strings.Contains(strings.ToLower(task.Target),strings.ToLower(target)) || task.Target == "all" {
			fmt.Printf("启动JSON插件集 %s\n", target)
			for _, plugin := range pluginList {
				if yes, res := jsonplugin.Check(task.Netloc, plugin); yes {
					ok = true
					fmt.Println("true:", res.Name)
					result = append(result, common.Struct2Map(res))
				}
			}
		}
	}
	return ok, result
}

// GetPlugins 获取插件信息
func GetPlugins()[]map[string]string{
	plugins := []map[string]string{}
	for name, pluginList := range Plugins {
		for _, plugin := range pluginList{
			info := plugin.Init()
			pluginMap := common.Struct2Map(info)
			delete(pluginMap, "request")
			delete(pluginMap, "response")
			pluginMap["target"] = name
			plugins = append(plugins,pluginMap)
		}
		for name, pluginList := range jsonplugin.JSONPlugins {
			for _, plugin := range pluginList{
				pluginMap := common.Struct2Map(plugin.Meta)
				delete(pluginMap, "request")
				delete(pluginMap, "response")
				pluginMap["target"] = name
				plugins = append(plugins,pluginMap)
			}
		}
	}
	return plugins
}