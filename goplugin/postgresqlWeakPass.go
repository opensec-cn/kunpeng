package goplugin

import (
	"database/sql"
	"fmt"
	"strings"
	"vuldb/plugin"
	"vuldb/common"
	_ "github.com/lib/pq"
)

type postgresqlWeakPass struct {
	info   common.PluginInfo
	result []common.PluginInfo
}

func init() {
	plugin.Regist("postgresql", &postgresqlWeakPass{})
}
func (d *postgresqlWeakPass) Init() common.PluginInfo{
	d.info = common.PluginInfo{
		Name:    "PostgreSQL 弱口令",
		Remarks: "导致数据库敏感信息泄露，严重可导致服务器直接被入侵控制。",
		Level:   1,
		Type:    "WEAK",
		Author:   "wolf",
		References: common.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}
func (d *postgresqlWeakPass) GetResult() []common.PluginInfo {
	return d.result
}
func (d *postgresqlWeakPass) Check(netloc string, meta plugin.TaskMeta) (b bool) {
	if strings.IndexAny(netloc,"http") == 0{
		return
	}
	userList := []string{
		"postgres", "admin",
	}
	for _, user := range userList {
		for _, pass := range PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s sslmode=disable", strings.Split(netloc, ":")[0], strings.Split(netloc, ":")[1], user, pass)
			db, err := sql.Open("postgres", connStr)
			// fmt.Println(connStr, err)
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
