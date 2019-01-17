package goplugin

import (
	"database/sql"
	"fmt"
	"strings"
	"github.com/opensec-cn/kunpeng/plugin"
	_ "github.com/go-sql-driver/mysql"
)

type mysqlWeakPass struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("mysql", &mysqlWeakPass{})
}
func (d *mysqlWeakPass) Init() plugin.Plugin{
	d.info = plugin.Plugin{
		Name:    "MySQL 弱口令",
		Remarks: "导致数据库敏感信息泄露，严重可导致服务器直接被入侵控制。",
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
func (d *mysqlWeakPass) GetResult() []plugin.Plugin {
	return d.result
}
func (d *mysqlWeakPass) Check(netloc string, meta plugin.TaskMeta) (b bool) {
	if strings.IndexAny(netloc,"http") == 0{
		return
	}
	userList := []string{
		"root", "www",
	}
	for _, user := range userList {
		for _, pass := range meta.PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			fmt.Println(pass)
			connStr := fmt.Sprintf("%s:%s@tcp(%s)/", user, pass, netloc)
			db, err := sql.Open("mysql", connStr)
			if err == nil && db.Ping() == nil {
				db.Close()
				result := d.info
				result.Request = connStr
				result.Remarks = fmt.Sprintf("弱口令：%s,%s,%s", user, pass, result.Remarks)
				d.result = append(d.result, result)
				b = true
				break
			}
		}
	}
	return b
}
