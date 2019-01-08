package goplugin

import (
	"net/http"
	"strings"
	"vuldb/common"
	"vuldb/plugin"
)

type iisPath struct {
	info   common.PluginInfo
	result []common.PluginInfo
}

func init() {
	plugin.Regist("iis", &iisPath{})
}
func (d *iisPath) Init() common.PluginInfo{
	d.info = common.PluginInfo{
		Name:    "IIS 物理路径泄露",
		Remarks: "通过访问一个不存在的文件或者目录，得到web物理路径",
		Level:   3,
		Type:    "INFO",
		Author:   "wolf",
		References: common.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}
func (d *iisPath) GetResult() []common.PluginInfo {
	return d.result
}
func (d *iisPath) Check(URL string, meta plugin.TaskMeta) bool {
	request400, err := http.NewRequest("GET", URL+"/404-test.asp", nil)
	if err != nil {
		return false
	}
	resp, err := common.RequestDo(request400, false)
	if err != nil {
		return false
	}
	if resp.Other.StatusCode == 404 && strings.Contains(resp.ResponseRaw, "0x80070002") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
