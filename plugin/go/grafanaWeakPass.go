package goplugin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type grafanaWeakPass struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("grafana", &grafanaWeakPass{})
}
func (d *grafanaWeakPass) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "grafana 控制台弱口令",
		Remarks: "攻击者通过此漏洞可以登陆管理控制台，读取相关连接认证信息。",
		Level:   1,
		Type:    "WEAKPWD",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://hackerone.com/reports/174883",
			KPID: "KP-0014",
		},
	}
	return d.info
}
func (d *grafanaWeakPass) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *grafanaWeakPass) Check(URL string, meta plugin.TaskMeta) bool {
	for _, pass := range meta.PassList {
		pass = strings.Replace(pass, "{user}", "admin", -1)
		loginData := fmt.Sprintf("{\"user\":\"admin\",\"email\":\"\",\"password\":%s}", pass)
		request, err := http.NewRequest("POST", URL+"/login", strings.NewReader(loginData))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := util.RequestDo(request, true)
		if err != nil {
			return false
		}
		if resp.Other.StatusCode == 404 {
			return false
		}
		if strings.Contains(resp.ResponseRaw, "Logged in") {
			result := d.info
			result.Response = resp.ResponseRaw
			result.Request = resp.RequestRaw
			result.Remarks = fmt.Sprintf("弱口令：admin:%s,%s", pass, result.Remarks)
			d.result = append(d.result, result)
			return true
		}
	}
	return false
}
