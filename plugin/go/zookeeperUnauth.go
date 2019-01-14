package goplugin

import (
	"fmt"
	"strings"
	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type zookeeperUnauth struct {
	info   plugin.PluginInfo
	result []plugin.PluginInfo
}

func init() {
	plugin.Regist("zookeeper", &zookeeperUnauth{})
}
func (d *zookeeperUnauth) Init() plugin.PluginInfo{
	d.info = plugin.PluginInfo{
		Name:    "zookeeper 未授权访问",
		Remarks: "导致敏感信息泄露。",
		Level:   2,
		Type:    "UNAUTH",
		Author:   "wolf",
		References: plugin.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}
func (d *zookeeperUnauth) GetResult() []plugin.PluginInfo {
	return d.result
}
func (d *zookeeperUnauth) Check(netloc string, meta plugin.TaskMeta) bool {
	if strings.IndexAny(netloc,"http") == 0{
		return false
	}
	buf,err := util.TCPSend(netloc,[]byte("envi"))
	if err == nil && strings.Contains(string(buf),"Environment") {
		result := d.info
		result.Request = fmt.Sprintf("zookeeper://%s", netloc)
		result.Response = string(buf)
		result.Remarks = fmt.Sprintf("未授权访问，%s", result.Remarks)
		d.result = append(d.result, result)
		return true
	}
	return false
}
