package goplugin

import (
	"fmt"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type memcacheUnauth struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("memcache", &memcacheUnauth{})
}
func (d *memcacheUnauth) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Memcache 未授权访问",
		Remarks: "导致敏感信息泄露。",
		Level:   2,
		Type:    "WEAKPWD",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://help.aliyun.com/knowledge_detail/37553.html",
			KPID: "KP-0008",
		},
	}
	return d.info
}
func (d *memcacheUnauth) GetResult() []plugin.Plugin {
	return d.result
}
func (d *memcacheUnauth) Check(netloc string, meta plugin.TaskMeta) bool {
	if strings.IndexAny(netloc, "http") == 0 {
		return false
	}
	buf, err := util.TCPSend(netloc, []byte("stats\r\n"))
	if err == nil && strings.Contains(string(buf), "STAT version") {
		result := d.info
		result.Request = fmt.Sprintf("memcache://%s", netloc)
		result.Response = string(buf)
		result.Remarks = fmt.Sprintf("未授权访问，%s", result.Remarks)
		d.result = append(d.result, result)
		return true
	}
	return false
}
