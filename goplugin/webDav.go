package goplugin

import (
	"net/http"
	"strings"
	"vuldb/common"
	"vuldb/plugin"
)

type webDav struct {
	info   common.PluginInfo
	result []common.PluginInfo
}

func init() {
	plugin.Regist("web", &webDav{})
}
func (d *webDav) Init() common.PluginInfo{
	d.info = common.PluginInfo{
		Name:    "WebDav Put开启",
		Remarks: "开启了WebDav且配置不当导致攻击者可上传文件到web目录",
		Level:   1,
		Type:    "CONF",
		Author:   "wolf",
		References: common.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}
func (d *webDav) GetResult() []common.PluginInfo {
	return d.result
}
func (d *webDav) Check(URL string, meta plugin.TaskMeta) bool {
	putURL := URL + "/" + getRandomString(6) + ".txt"
	request, err := http.NewRequest("PUT", putURL, strings.NewReader("vultest"))
	if err != nil {
		return false
	}
	_, err = common.RequestDo(request, false)
	if err != nil {
		return false
	}
	vRequest, err := http.NewRequest("GET", putURL, nil)
	if err != nil {
		return false
	}
	resp, err := common.RequestDo(vRequest, true)
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
