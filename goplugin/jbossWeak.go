package goplugin

import (
	"fmt"
	"net/http"
	"strings"
	"vuldb/common"
	"vuldb/plugin"
)

type jbossWeak struct {
	info   common.PluginInfo
	result []common.PluginInfo
}

func init() {
	plugin.Regist("jboss", &jbossWeak{})
}
func (d *jbossWeak) Init() common.PluginInfo{
	d.info = common.PluginInfo{
		Name:    "JBoss 控制台弱口令",
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
func (d *jbossWeak) GetResult() []common.PluginInfo {
	return d.result
}
func (d *jbossWeak) Check(URL string, meta plugin.TaskMeta) bool {
	loginURLList := []string{
		"/jmx-console/",
		"/console/App.html",
	}
	var loginURL string
	for _, login := range loginURLList {
		request, err := http.NewRequest("GET", URL+login, nil)
		if err != nil {
			continue
		}
		resp, err := common.RequestDo(request, false)
		if err != nil {
			continue
		}
		if resp.Other.StatusCode == 401 {
			loginURL = URL + login
			break
		}
	}
	if loginURL == "" {
		return false
	}
	userList := []string{
		"admin", "jboss", "root",
	}
	//flagList := []string{
	//	`\>jboss\.j2ee<\/a>`,
	//		`JBoss JMX Management Console`,
	//		`HtmlAdaptor\?action\=displayMBeans`,
	//		`<title>JBoss Management`,
	//	}
	for _, user := range userList {
		for _, pass := range PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			request, _ := http.NewRequest("GET", loginURL, nil)
			request.SetBasicAuth(user, pass)
			// log.Println(user, pass)
			resp, err := common.RequestDo(request, false)
			if err != nil {
				continue
			}
			// log.Println(responseRaw)
			if resp.Other.StatusCode == 200 && strings.Contains(resp.Other.Header.Get("Set-Cookie"), "Path=/jmx-console") {
				result := d.info
				result.Response = resp.ResponseRaw
				result.Request = resp.RequestRaw
				result.Remarks = fmt.Sprintf("弱口令：%s,%s,%s", user, pass, result.Remarks)
				d.result = append(d.result, result)
				return true
			}
		}
	}
	return false
}
