package goplugin

import (
	"fmt"
	"net/http"
	"strings"
	"vuldb/common"
	"vuldb/plugin"
)

type tomcatWeakPass struct {
	info   common.PluginInfo
	result []common.PluginInfo
}

func init() {
	plugin.Regist("tomcat", &tomcatWeakPass{})
}
func (d *tomcatWeakPass) Init() common.PluginInfo{
	d.info = common.PluginInfo{
		Name:    "Apache Tomcat 弱口令",
		Remarks: "攻击者通过此漏洞可以登陆管理控制台，通过部署功能可直接获取服务器权限。",
		Level:   0,
		Type:    "WEAK",
		Author:   "wolf",
		References: common.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}
func (d *tomcatWeakPass) GetResult() []common.PluginInfo {
	return d.result
}
func (d *tomcatWeakPass) Check(URL string, meta plugin.TaskMeta) bool {
	userList := []string{
		"admin", "tomcat", "apache", "root", "manager",
	}
	for _, user := range userList {
		for _, pass := range PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			request, err := http.NewRequest("GET", URL+"/manager/html", nil)
			request.SetBasicAuth(user, pass)
			resp, err := common.RequestDo(request, true)
			if err != nil {
				return false
			}
			if resp.Other.StatusCode == 404 {
				return false
			}
			if resp.Other.StatusCode == 200 {
				if strings.Contains(resp.ResponseRaw, "/manager/html/reload") || strings.Contains(resp.ResponseRaw, "Tomcat Web Application Manager") {
					result := d.info
					result.Response = resp.ResponseRaw
					result.Request = resp.RequestRaw
					result.Remarks = fmt.Sprintf("弱口令：%s,%s,%s", user, pass, result.Remarks)
					d.result = append(d.result, result)
					return true
				}
				//200 又没关键字的可能不是tomcat
				return false
			}
		}
	}
	return false
}
