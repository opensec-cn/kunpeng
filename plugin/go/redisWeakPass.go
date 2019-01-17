package goplugin

import (
	"fmt"
	"strings"

	"github.com/go-redis/redis"
	"github.com/opensec-cn/kunpeng/plugin"
)

type redisWeakPass struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("redis", &redisWeakPass{})
}
func (d *redisWeakPass) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Redis 未授权访问/弱口令",
		Remarks: "导致敏感信息泄露，严重可导致服务器直接被入侵控制。",
		Level:   0,
		Type:    "WEAKPWD",
		Author:  "wolf",
		References: plugin.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}
func (d *redisWeakPass) GetResult() []plugin.Plugin {
	return d.result
}
func (d *redisWeakPass) Check(netloc string, meta plugin.TaskMeta) bool {
	if strings.IndexAny(netloc, "http") == 0 {
		return false
	}
	for _, pass := range meta.PassList {
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
