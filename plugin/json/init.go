package jsonplugin

import (
	"encoding/json"
	. "github.com/opensec-cn/kunpeng/config"
	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

var extraPluginCache []string

func init() {
	// util.Logger.Println("init json plugin")
	loadJSONPlugin(false, "/plugin/json/")
	go loadExtraJSONPlugin()
}

func readPlugin(useLocal bool, filePath string) (p plugin.JSONPlugin, ok bool) {
	// util.Logger.Println(filePath)
	var pluginBytes []byte
	var err error
	// util.Logger.Println(path.Ext(filePath))
	if strings.ToLower(path.Ext(filePath)) != ".json" {
		return p, false
	}
	if useLocal {
		pluginBytes, err = ioutil.ReadFile(filePath)
		if err != nil {
			util.Logger.Error(err.Error(), filePath)
			return p, false
		}
	} else {
		pluginBytes = FSMustByte(useLocal, filePath)
	}
	err = json.Unmarshal(pluginBytes, &p)
	if err != nil {
		util.Logger.Error(err.Error(), string(pluginBytes))
		return p, false
	}
	p.Extra = useLocal
	return p, true
}

func loadJSONPlugin(useLocal bool, pluginPath string) {
	var f http.File
	var err error
	if useLocal {
		f, err = os.Open(pluginPath)
		if err != nil {
			util.Logger.Error(err.Error())
			return
		}
	} else {
		f, err = FS(useLocal).Open(pluginPath)
		if err != nil {
			util.Logger.Error(err.Error())
			return
		}
	}
	defer f.Close()
	fileList, err := f.Readdir(2000)
	if err != nil {
		util.Logger.Error(err.Error(), pluginPath)
		return
	}
	var extarPluginNameList []string
	for _, v := range fileList {
		p, ok := readPlugin(useLocal, pluginPath+v.Name())
		if !ok {
			continue
		}
		if p.Extra == true {
			extarPluginNameList = append(extarPluginNameList, p.Meta.Name)
		}
		// 防止重复加载
		if len(p.Meta.Name) == 0 || util.InArray(extraPluginCache, p.Meta.Name, false) {
			continue
		} else {
			if useLocal == true {
				util.Logger.Warning("init plugin:", p.Meta.References.KPID, p.Meta.Name)
			}
			plugin.JSONPlugins[p.Target] = append(plugin.JSONPlugins[p.Target], p)
			extraPluginCache = append(extraPluginCache, p.Meta.Name)
		}
	}
	ExtarPluginList := getExtarPluginList()
	for _, v := range ExtarPluginList {
		if util.InArray(extarPluginNameList, v.Meta.Name, false) == false {
			util.Logger.Warning("delete plugin:", v.Meta.Name)
			plugin.JSONPlugins[v.Target] = getNewPluginList(plugin.JSONPlugins[v.Target], v.Meta.Name)
			util.DeleteSliceValue(&extraPluginCache, v.Meta.Name)
		}
	}
}

func getExtarPluginList() (ExtarPluginList []plugin.JSONPlugin) {
	for _, v := range plugin.JSONPlugins {
		for _, p := range v {
			if p.Extra == true {
				ExtarPluginList = append(ExtarPluginList, p)
			}
		}
	}
	return ExtarPluginList
}

func getNewPluginList(oldPluginList []plugin.JSONPlugin, name string) []plugin.JSONPlugin {
	newPluginList := make([]plugin.JSONPlugin, 0, len(oldPluginList))
	for _, p := range oldPluginList {
		if p.Meta.Name != name {
			newPluginList = append(newPluginList, p)
		}
	}
	return newPluginList
}

func loadExtraJSONPlugin() {
	// ticker := time.NewTicker(time.Second * 3)
	for {
		if len(Config.ExtraPluginPath) >= 1 {
			loadJSONPlugin(true, Config.ExtraPluginPath)
		}
		time.Sleep(time.Second * 20)
	}
}
