package goplugin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type jbossWeak struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("jboss", &jbossWeak{})
}
func (d *jbossWeak) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "JBoss 控制台弱口令",
		Remarks: "攻击者通过此漏洞可以登陆管理控制台，通过部署功能可直接获取服务器权限。",
		Level:   0,
		Type:    "WEAKPWD",
		Author:  "wolf",
		References: plugin.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}
func (d *jbossWeak) GetResult() []plugin.Plugin {
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
		resp, err := util.RequestDo(request, false)
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
		for _, pass := range meta.PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			request, _ := http.NewRequest("GET", loginURL, nil)
			request.SetBasicAuth(user, pass)
			// log.Println(user, pass)
			resp, err := util.RequestDo(request, false)
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
