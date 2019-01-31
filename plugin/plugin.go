// Package plugin 加载插件、执行插件、获取插件信息，支持JSON和Go插件
package plugin

import (
	"strings"

	. "github.com/opensec-cn/kunpeng/config"
	"github.com/opensec-cn/kunpeng/util"
)

// GoPlugins GO插件集
var GoPlugins map[string][]GoPlugin

// JSONPlugins JSON插件集
var JSONPlugins map[string][]JSONPlugin

// Task 任务结构
type Task struct {
	Type   string   `json:"type"`
	Netloc string   `json:"netloc"`
	Target string   `json:"target"`
	Meta   TaskMeta `json:"meta"`
}

// TaskMeta 任务额外信息
type TaskMeta struct {
	System   string   `json:"system"`
	PathList []string `json:"pathlist"`
	FileList []string `json:"filelist"`
	PassList []string `json:"passlist"`
}

//References 插件附加信息
type References struct {
	URL string `json:"url"`
	CVE string `json:"cve"`
}

// Plugin 漏洞插件信息
type Plugin struct {
	Name       string     `json:"name"`
	Remarks    string     `json:"remarks"`
	Level      int        `json:"level"`
	Type       string     `json:"type"`
	Author     string     `json:"author"`
	References References `json:"references"`
	Request    string
	Response   string
}

func init() {
	GoPlugins = make(map[string][]GoPlugin)
	JSONPlugins = make(map[string][]JSONPlugin)
}

// Scan 开始插件扫描
func Scan(task Task) (result []map[string]interface{}) {
	if strings.Contains(strings.ToLower(task.Netloc),string([]byte{103, 111, 118, 46, 99, 110})){
		return result
	}
	util.Logger.Info("new task:",task)
	util.Logger.Info("go plugin total:",len(GoPlugins))
	// GO插件
	for n, pluginList := range GoPlugins {
		if strings.Contains(strings.ToLower(task.Target), strings.ToLower(n)) || task.Target == "all" {
			util.Logger.Info("run go plugins:",n)
			for _, plugin := range pluginList {
				plugin.Init()
				if len(task.Meta.PassList) == 0 {
					task.Meta.PassList = Config.PassList
				}
				if !plugin.Check(task.Netloc, task.Meta) {
					continue
				}
				for _, res := range plugin.GetResult() {
					util.Logger.Info("hit plugin:",res.Name)
					result = append(result, util.Struct2Map(res))
				}
			}
		}
	}
	if task.Type == "service" {
		return result
	}
	// JSON插件
	util.Logger.Info("JSON Plugin total: ",len(JSONPlugins))
	for target, pluginList := range JSONPlugins {
		if strings.Contains(strings.ToLower(task.Target), strings.ToLower(target)) || task.Target == "all" {
			util.Logger.Info("run go plugins:",target)
			for _, plugin := range pluginList {
				if yes, res := jsonCheck(task.Netloc, plugin); yes {
					util.Logger.Info("hit plugin:",res.Name)
					result = append(result, util.Struct2Map(res))
				}
			}
		}
	}
	return result
}

// GetPlugins 获取插件信息
func GetPlugins() (plugins []map[string]interface{}) {
	for name, pluginList := range GoPlugins {
		for _, plugin := range pluginList {
			info := plugin.Init()
			pluginMap := util.Struct2Map(info)
			delete(pluginMap, "request")
			delete(pluginMap, "response")
			pluginMap["target"] = name
			plugins = append(plugins, pluginMap)
		}
		for name, pluginList := range JSONPlugins {
			for _, plugin := range pluginList {
				pluginMap := util.Struct2Map(plugin.Meta)
				delete(pluginMap, "request")
				delete(pluginMap, "response")
				pluginMap["target"] = name
				plugins = append(plugins, pluginMap)
			}
		}
	}
	return plugins
}
