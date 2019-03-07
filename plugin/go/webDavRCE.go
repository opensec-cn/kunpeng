package goplugin

import (
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type webDavRCE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("iis", &webDavRCE{})
}
func (d *webDavRCE) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "WebDav PROPFIND RCE(理论检测)",
		Remarks: "Windows Server 2003R2版本IIS6.0的WebDAV服务中的ScStoragePathFromUrl函数存在缓存区溢出漏洞",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://www.seebug.org/vuldb/ssvid-92834",
			CVE:  "CVE-2017-7269",
			KPID: "KP-0023",
		},
	}
	return d.info
}
func (d *webDavRCE) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
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
