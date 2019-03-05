package goplugin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type directoryBrowse struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("web", &directoryBrowse{})
}
func (d *directoryBrowse) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "web目录浏览",
		Remarks: "通过此功能可获取web目录程序结构",
		Level:   3,
		Type:    "INFO",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://blog.csdn.net/wutianxu123/article/details/82634893",
			KPID: "KP-0013",
		},
	}
	return d.info
}
func (d *directoryBrowse) GetResult() []plugin.Plugin {
	return d.result
}
func (d *directoryBrowse) Check(URL string, meta plugin.TaskMeta) bool {
	u, err := url.Parse(URL)
	if err != nil {
		return false
	}
	flagList := []string{
		`<title>index of \/`,
		`<title>directory listing for`,
		fmt.Sprintf("<title>%s - /", u.Hostname()),
	}
	pathList := append(meta.PathList, []string{URL, URL + "/css/", URL + "/js/", URL + "/img/", URL + "/images/", URL + "/upload/", URL + "/inc/"}...)
	for _, pathURL := range pathList {
		request, err := http.NewRequest("GET", pathURL, nil)
		resp, err := util.RequestDo(request, true)
		if err != nil {
			return false
		}
		if resp.Other.StatusCode == 404 {
			continue
		}
		if util.InArray(flagList, strings.ToLower(resp.ResponseRaw), true) {
			result := d.info
			result.Response = resp.ResponseRaw
			result.Request = resp.RequestRaw
			d.result = append(d.result, result)
			return true
		}
	}
	return false
}
