package goplugin

import (
	"fmt"
	"strings"
	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/go-redis/redis"
)

type redisWeakPass struct {
	info   plugin.PluginInfo
	result []plugin.PluginInfo
}

func init() {
	plugin.Regist("redis", &redisWeakPass{})
}
func (d *redisWeakPass) Init() plugin.PluginInfo{
	d.info = plugin.PluginInfo{
		Name:    "Redis 未授权访问/弱口令",
		Remarks: "导致敏感信息泄露，严重可导致服务器直接被入侵控制。",
		Level:   0,
		Type:    "WEAK",
		Author:   "wolf",
		References: plugin.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}
func (d *redisWeakPass) GetResult() []plugin.PluginInfo {
	return d.result
}
func (d *redisWeakPass) Check(netloc string, meta plugin.TaskMeta) bool {
	if strings.IndexAny(netloc,"http") == 0{
		return false
	}
	for _, pass := range PassList {
		client := redis.NewClient(&redis.Options{
			Addr:     netloc,
			Password: pass,
			DB:       0,
		})
		_, err := client.Ping().Result()
		if err == nil {
			client.Close()
			result := d.info
			result.Request = fmt.Sprintf("redis://%s@%s", pass, netloc)
			if pass == "" {
				result.Remarks = fmt.Sprintf("未授权访问，%s", result.Remarks)
			} else {
				result.Remarks = fmt.Sprintf("弱口令：%s,%s", pass, result.Remarks)
			}
			d.result = append(d.result, result)
			return true
		}
	}
	return false
}
