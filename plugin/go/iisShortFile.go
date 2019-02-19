package goplugin

import (
	"net/http"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type iisShortFile struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("iis", &iisShortFile{})
}
func (d *iisShortFile) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "IIS 短文件名枚举",
		Remarks: "攻击者可利用此特性猜解出目录与文件名，以达到类似列目录漏洞的效果",
		Level:   3,
		Type:    "INFO",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://www.freebuf.com/articles/web/172561.html",
			KPID: "KP-0017",
		},
	}
	return d.info
}
func (d *iisShortFile) GetResult() []plugin.Plugin {
	return d.result
}
func (d *iisShortFile) Check(URL string, meta plugin.TaskMeta) bool {
	request400, err := http.NewRequest("GET", URL+"/otua*~1.*/.aspx", nil)
	if err != nil {
		return false
	}
	resp, err := util.RequestDo(request400, false)
	if err != nil {
		return false
	}
	if resp.Other.StatusCode == 400 {
		request404, err := http.NewRequest("GET", URL+"/*~1.*/.aspx", nil)
		if err != nil {
			return false
		}
		resp, err := util.RequestDo(request404, true)
		if err != nil {
			return false
		}
		if resp.Other.StatusCode == 404 {
			result := d.info
			result.Response = resp.ResponseRaw
			result.Request = resp.RequestRaw
			d.result = append(d.result, result)
			return true
		}
	}
	return false
}
