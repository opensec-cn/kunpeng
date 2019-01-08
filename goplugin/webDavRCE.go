package goplugin

import (
	"net/http"
	"strings"
	"github.com/opensec-cn/kunpeng/util"
	"github.com/opensec-cn/kunpeng/plugin"
)

type webDavRCE struct {
	info   plugin.PluginInfo
	result []plugin.PluginInfo
}

func init() {
	plugin.Regist("iis", &webDavRCE{})
}
func (d *webDavRCE) Init() plugin.PluginInfo{
	d.info = plugin.PluginInfo{
		Name:    "WebDav PROPFIND RCE(理论检测)",
		Remarks: "CVE-2017-7269,Windows Server 2003R2版本IIS6.0的WebDAV服务中的ScStoragePathFromUrl函数存在缓存区溢出漏洞",
		Level:   1,
		Type:    "RCE",
		Author:   "wolf",
		References: plugin.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}
func (d *webDavRCE) GetResult() []plugin.PluginInfo {
	return d.result
}
func (d *webDavRCE) Check(URL string, meta plugin.TaskMeta) bool {
	request, err := http.NewRequest("OPTIONS", URL, nil)
	if err != nil {
		return false
	}
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if resp.Other.Header.Get("Server") == "Microsoft-IIS/6.0" && strings.Contains(resp.Other.Header.Get("Allow"), "PROPFIND") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
