package goplugin

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	. "github.com/opensec-cn/kunpeng/config"
	"github.com/opensec-cn/kunpeng/plugin"
)

type mysqlWeakPass struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("mysql", &mysqlWeakPass{})
}
func (d *mysqlWeakPass) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "MySQL 弱口令",
		Remarks: "导致数据库敏感信息泄露，严重可导致服务器直接被入侵控制。",
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
func (d *mysqlWeakPass) GetResult() []plugin.Plugin {
	return d.result
}
func (d *mysqlWeakPass) Check(netloc string, meta plugin.TaskMeta) (b bool) {
	if strings.IndexAny(netloc, "http") == 0 {
		return
	}
	userList := []string{
		"root", "www", "bbs", "web", "admin",
	}
	for _, user := range userList {
		for _, pass := range meta.PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			connStr := fmt.Sprintf("%s:%s@tcp(%s)/?timeout=%ds", user, pass, netloc, Config.Timeout)
			db, err := sql.Open("mysql", connStr)
			if err != nil {
				break
			}
			err = db.Ping()
			if err == nil {
				db.Close()
				result := d.info
				result.Request = connStr
				result.Remarks = fmt.Sprintf("弱口令：%s,%s,%s", user, pass, result.Remarks)
				d.result = append(d.result, result)
				b = true
				break
			} else if strings.Contains(err.Error(), "Access denied") {
				continue
			} else {
				return
			}
		}
	}
	return b
}
