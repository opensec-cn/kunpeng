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
	util.Logger.Println("init json plugin")
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
	fileList, err := f.Readdir(2000)
	if err != nil {
		util.Logger.Error(err.Error(), pluginPath)
		return
	}
	for _, v := range fileList {
		p, ok := readPlugin(useLocal, pluginPath+v.Name())
		if !ok {
			continue
		}
		// 防止重复加载
		if len(p.Meta.Name) == 0 || util.InArray(extraPluginCache, p.Meta.Name, false) {
			continue
		} else {
			util.Logger.Println("init plugin:", p.Meta.References.KPID, p.Meta.Name)
			plugin.JSONPlugins[p.Target] = append(plugin.JSONPlugins[p.Target], p)
			extraPluginCache = append(extraPluginCache, p.Meta.Name)
		}
	}
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
