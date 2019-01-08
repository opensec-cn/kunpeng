package goplugin

import (
	"strings"
	"fmt"
	"net/http"
	"net/url"
	"vuldb/common"
	"vuldb/plugin"
)

type directoryBrowse struct {
	info   common.PluginInfo
	result []common.PluginInfo
}

func init() {
	plugin.Regist("web", &directoryBrowse{})
}
func (d *directoryBrowse) Init() common.PluginInfo{
	d.info = common.PluginInfo{
		Name:    "web目录遍历",
		Remarks: "通过此功能可获取web目录程序结构",
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
func (d *directoryBrowse) GetResult() []common.PluginInfo {
	return d.result
}
func (d *directoryBrowse) Check(URL string, meta plugin.TaskMeta) bool {
	u, _ := url.Parse(URL)
	flagList := []string{
		`<title>index of \/`,
		`<title>directory listing for`,
		fmt.Sprintf("<title>%s - /", u.Hostname()),
	}
	pathList := append(meta.PathList, []string{URL, URL + "/css/", URL + "/js/", URL + "/img/", URL + "/images/", URL + "/upload/", URL + "/inc/"}...)
	for _, pathURL := range pathList {
		// fmt.Println(pathURL)
		request, err := http.NewRequest("GET", pathURL, nil)
		resp, err := common.RequestDo(request, true)
		if err != nil {
			return false
		}
		// fmt.Println(resp.ResponseRaw)
		if resp.Other.StatusCode == 404 {
			continue
		}
		if inArray(flagList, strings.ToLower(resp.ResponseRaw), true) {
			result := d.info
			result.Response = resp.ResponseRaw
			result.Request = resp.RequestRaw
			d.result = append(d.result, result)
			return true
		}
	}
	return false
}
