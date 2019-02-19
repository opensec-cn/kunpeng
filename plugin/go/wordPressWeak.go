package goplugin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type wordPressWeak struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("wordpress", &wordPressWeak{})
}
func (d *wordPressWeak) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "WordPress 后台弱口令",
		Remarks: "攻击者通过此漏洞可以登陆管理后台，通过编辑插件功能可写入webshell，最终导致服务器被入侵控制。",
		Level:   0,
		Type:    "WEAKPWD",
		Author:  "wolf",
		References: plugin.References{
			KPID: "KP-0026",
		},
	}
	return d.info
}
func (d *wordPressWeak) GetResult() []plugin.Plugin {
	return d.result
}
func (d *wordPressWeak) getUserList(URL string) (userList []string) {
	errorFlag := "error-404 not-found"
	for i := 1; i < 10; i++ {
		var user string
		url := fmt.Sprintf("%s/?author=%d", URL, i)
		request, _ := http.NewRequest("GET", url, nil)
		resp, err := util.RequestDo(request, false)
		if err != nil || strings.Contains(string(resp.Body), errorFlag) {
			return
		}
		tmpList := strings.Split(resp.Other.Request.URL.String(), "/author/")
		if len(tmpList) == 2 {
			user = strings.TrimSpace(strings.Trim(tmpList[1], "/"))
			if user == "" {
				return
			}
			userList = append(userList, user)
		}
	}
	return
}

func (d *wordPressWeak) Check(URL string, meta plugin.TaskMeta) bool {
	userList := d.getUserList(URL)
	if len(userList) == 0 {
		userList = []string{"admin"}
	}
	for _, user := range userList {
		for _, pass := range meta.PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			postData := "<?xml version='1.0' encoding='iso-8859-1'?><methodCall>  <methodName>wp.getUsersBlogs</methodName>  " +
				"<params>   <param><value>%s</value></param>   <param><value>%s</value></param>  </params></methodCall>"
			request, err := http.NewRequest("POST", URL+"/xmlrpc.php", strings.NewReader(fmt.Sprintf(postData, user, pass)))
			resp, err := util.RequestDo(request, true)
			if err != nil {
				return false
			}
			if resp.Other.StatusCode == 404 {
				return false
			}
			if strings.Contains(resp.ResponseRaw, "<name>blogName</name>") {
				result := d.info
				result.Response = resp.ResponseRaw
				result.Request = resp.RequestRaw
				result.Remarks = fmt.Sprintf("弱口令：%s,%s,%s", user, pass, result.Remarks)
				d.result = append(d.result, result)
				break
			}
		}
	}
	if len(d.result) >= 1 {
		return true
	}
	return false
}
