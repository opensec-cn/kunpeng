package goplugin

import (
	"database/sql"
	"fmt"
	"strings"
	"github.com/opensec-cn/kunpeng/plugin"
	_ "github.com/denisenkom/go-mssqldb"
)

type mssqlWeakPass struct {
	info   plugin.PluginInfo
	result []plugin.PluginInfo
}

func init() {
	plugin.Regist("mssql", &mssqlWeakPass{})
}
func (d *mssqlWeakPass) Init() plugin.PluginInfo{
	d.info = plugin.PluginInfo{
		Name:    "SQLServer 弱口令",
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
func (d *mssqlWeakPass) GetResult() []plugin.PluginInfo {
	return d.result
}
func (d *mssqlWeakPass) Check(netloc string, meta plugin.TaskMeta) (b bool) {
	if strings.IndexAny(netloc,"http") == 0{
		return
	}
	userList := []string{
		"sa",
	}
	for _, user := range userList {
		for _, pass := range meta.PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			connStr := fmt.Sprintf("sqlserver://%s:%s@%s", user, pass, netloc)
			db, err := sql.Open("mssql", connStr)
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
