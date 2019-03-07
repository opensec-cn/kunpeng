package goplugin

import (
	"database/sql"
	"fmt"
	"github.com/opensec-cn/kunpeng/util"
	"strings"

	_ "github.com/lib/pq"
	. "github.com/opensec-cn/kunpeng/config"
	"github.com/opensec-cn/kunpeng/plugin"
)

type postgresqlWeakPass struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("postgresql", &postgresqlWeakPass{})
}
func (d *postgresqlWeakPass) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "PostgreSQL 弱口令",
		Remarks: "导致数据库敏感信息泄露，严重可导致服务器直接被入侵控制。",
		Level:   1,
		Type:    "WEAKPWD",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://helpcdn.aliyun.com/knowledge_detail/37544.html",
			KPID: "KP-0004",
		},
	}
	return d.info
}
func (d *postgresqlWeakPass) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *postgresqlWeakPass) Check(netloc string, meta plugin.TaskMeta) (b bool) {
	if strings.IndexAny(netloc, "http") == 0 {
		return
	}
	userList := []string{
		"postgres", "admin",
	}
	host, port := util.ParseNetLoc(netloc)
	if port == 0 {
		port = 5432
	}
	for _, user := range userList {
		for _, pass := range meta.PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=disable connect_timeout=%d",
				host, port, user, pass, Config.Timeout)
			db, err := sql.Open("postgres", connStr)
			err = db.Ping()
			if err == nil {
				db.Close()
				result := d.info
				result.Request = connStr
				result.Remarks = fmt.Sprintf("弱口令：%s,%s,%s", user, pass, result.Remarks)
				d.result = append(d.result, result)
				b = true
				break
			} else if strings.Contains(err.Error(), "authentication failed") {
				continue
			} else {
				return
			}
		}
	}
	return
}
