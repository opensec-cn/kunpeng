package goplugin

import (
	"fmt"
	"net/http"
	"strings"
	"vuldb/common"
	"vuldb/plugin"
)

type weblogicWeak struct {
	info   common.PluginInfo
	result []common.PluginInfo
}

func init() {
	plugin.Regist("weblogic", &weblogicWeak{})
}
func (d *weblogicWeak) Init() common.PluginInfo{
	d.info = common.PluginInfo{
		Name:    "Weblogic 控制台弱口令",
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
func (d *weblogicWeak) GetResult() []common.PluginInfo {
	return d.result
}
func (d *weblogicWeak) Check(URL string, meta plugin.TaskMeta) bool {
	loginURL := URL + "/console/j_security_check"
	request, _ := http.NewRequest("GET", loginURL, nil)
	resp, err := common.RequestDo(request, true)
	if err != nil {
		return false
	}
	if !strings.Contains(resp.ResponseRaw, "input") {
		return false
	}
	userList := []string{
		"weblogic", "admin",
	}
	flagList := []string{
		`<title>WebLogic Server Console<\/title>`,
		`javascript\/console-help\.js`,
		`WebLogic Server Administration Console Home`,
		`\/console\/console\.portal`,
		`console\/jsp\/common\/warnuserlockheld\.jsp`,
		`\/console\/actions\/common\/`,
	}
	for _, user := range userList {
		for _, pass := range PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			postData := fmt.Sprintf("j_username=%s&j_password=%s&j_character_encoding=UTF-8", user, pass)
			request, err := http.NewRequest("POST", loginURL, strings.NewReader(postData))
			if err != nil {
				continue
			}
			resp, err := common.RequestDo(request, true)
			if err != nil {
				continue
			}
			if resp.Other.StatusCode == 200 && inArray(flagList, resp.ResponseRaw, true) {
				result := d.info
				result.Response = resp.ResponseRaw
				result.Request = resp.RequestRaw
				result.Remarks = fmt.Sprintf("弱口令:%s,%s,", user, pass) + result.Remarks
				d.result = append(d.result, result)
				return true
			}
		}
	}
	return false
}
