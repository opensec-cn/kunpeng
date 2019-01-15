package plugin

import (
	"strings"
	"fmt"
	"github.com/opensec-cn/kunpeng/util"
	. "github.com/opensec-cn/kunpeng/config"
)

// GoPlugins GO插件集
var GoPlugins map[string][]GoPlugin

// JSONPlugins JSON插件集
var JSONPlugins map[string][]JSONPlugin

// TaskInfo 任务结构
type TaskInfo struct {
	Type string `json:"type"`
	Netloc string `json:"netloc"`
	Target string `json:"target"`
	Meta TaskMeta `json:"meta"`
}

// TaskMeta 任务额外信息
type TaskMeta struct{
	System string `json:"system"`
	PathList []string `json:"pathlist"`
	FileList []string `json:"filelist"`
	PassList []string `json:"passlist"`
}

//References 插件附加信息
type References struct{
	URL string `json:"url"`
	CVE string `json:"cve"`
}

// PluginInfo 漏洞插件信息
type PluginInfo struct {
	Name     string `json:"name"`
	Remarks  string `json:"remarks"`
	Level    int `json:"level"`
	Type     string `json:"type"`
	Author	 string `json:"author"`
	References References `json:"references"`
	Request  string
	Response string
}


func init() {
	GoPlugins = make(map[string][]GoPlugin)
	JSONPlugins = make(map[string][]JSONPlugin)
}


// Scan 开始插件扫描
func Scan(task TaskInfo) (result []map[string]string) {
	// GO插件
	for n, pluginList := range GoPlugins {
		if strings.Contains(strings.ToLower(task.Target),strings.ToLower(n)) || task.Target == "all" {
			fmt.Printf("启动插件集 %s\n", n)
			for _, plugin := range pluginList {
				plugin.Init()
				if len(task.Meta.PassList) == 0{
					task.Meta.PassList = Config.PassList
				}
				if !plugin.Check(task.Netloc, task.Meta) {
					continue
				}
				for _, res := range plugin.GetResult() {
					fmt.Println("true:", res.Name)
					result = append(result, util.Struct2Map(res))
				}
			}
		}
	}
	if task.Type == "service" {
		return result
	}
	// JSON插件
	for target, pluginList := range JSONPlugins {
		if strings.Contains(strings.ToLower(task.Target),strings.ToLower(target)) || task.Target == "all" {
			fmt.Printf("启动JSON插件集 %s\n", target)
			for _, plugin := range pluginList {
				if yes, res := jsonCheck(task.Netloc, plugin); yes {
					fmt.Println("true:", res.Name)
					result = append(result, util.Struct2Map(res))
				}
			}
		}
	}
	return result
}

// GetPlugins 获取插件信息
func GetPlugins()(plugins []map[string]interface{}){
	for name, pluginList := range GoPlugins {
		for _, plugin := range pluginList{
			info := plugin.Init()
			pluginMap := util.Struct2Map(info)
			delete(pluginMap, "request")
			delete(pluginMap, "response")
			pluginMap["target"] = name
			plugins = append(plugins,pluginMap)
		}
		for name, pluginList := range JSONPlugins {
			for _, plugin := range pluginList{
				pluginMap := util.Struct2Map(plugin.Meta)
				delete(pluginMap, "request")
				delete(pluginMap, "response")
				pluginMap["target"] = name
				plugins = append(plugins,pluginMap)
			}
		}
	}
	return plugins
}