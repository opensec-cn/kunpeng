package goplugin

import (
	"fmt"
	"strings"
	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/jlaffaye/ftp"
)

type ftpWeakPass struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("ftp", &ftpWeakPass{})
}
func (d *ftpWeakPass) Init() plugin.Plugin{
	d.info = plugin.Plugin{
		Name:    "FTP 弱口令",
		Remarks: "导致敏感信息泄露，严重可导致服务器直接被入侵控制。",
		Level:   1,
		Type:    "WEAK",
		Author:   "wolf",
		References: plugin.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}
func (d *ftpWeakPass) GetResult() []plugin.Plugin {
	return d.result
}
func (d *ftpWeakPass) Check(netloc string, meta plugin.TaskMeta) (b bool) {
	if strings.IndexAny(netloc,"http") == 0{
		return
	}
	userList := []string{
		"root", "admin", "www", "ftp",
	}
	for _, user := range userList {
		for _, pass := range meta.PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			conn, err := ftp.Connect(netloc)
			if err != nil {
				return
			}
			err = conn.Login(user, pass)
			if err == nil {
				conn.Logout()
				result := d.info
				if user == "ftp" {
					result.Remarks = fmt.Sprintf("匿名登录,%s", result.Remarks)
				} else {
					result.Remarks = fmt.Sprintf("弱口令：%s,%s,%s", user, pass, result.Remarks)
				}
				result.Request = fmt.Sprintf("ftp://%s:%s@%s", user, pass, netloc)
				d.result = append(d.result, result)
				b = true
				return
			}
		}
	}
	return b
}
