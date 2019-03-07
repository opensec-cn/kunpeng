package goplugin

import (
	"fmt"
	"github.com/opensec-cn/kunpeng/util"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/stacktitan/smb/smb"
)

type smbWeakPass struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("smb", &smbWeakPass{})
}
func (d *smbWeakPass) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "SMB 匿名共享/弱口令",
		Remarks: "敏感文件被窃取，SMB通常使用系统账户密码进行验证，严重可导致服务器直接被入侵控制。",
		Level:   0,
		Type:    "WEAKPWD",
		Author:  "wolf",
		References: plugin.References{
			KPID: "KP-0002",
		},
	}
	return d.info
}
func (d *smbWeakPass) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *smbWeakPass) Check(netloc string, meta plugin.TaskMeta) (b bool) {
	if strings.IndexAny(netloc, "http") == 0 {
		return
	}
	userList := []string{
		"administrator",
	}
	options := smb.Options{
		Host:        strings.Split(netloc, ":")[0],
		Port:        445,
		User:        "",
		Domain:      "",
		Workstation: "workgroup",
		Password:    "",
	}
	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		result := d.info
		result.Request = fmt.Sprintf("smb://%s", netloc)
		result.Remarks = "匿名共享," + result.Remarks
		result.Level = 4
		d.result = append(d.result, result)
		return true
	}
	host, port := util.ParseNetLoc(netloc)
	if port == 0 {
		port = 445
	}
	for _, user := range userList {
		for _, pass := range meta.PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			options := smb.Options{
				Host:        host,
				Port:        port,
				User:        user,
				Domain:      "",
				Workstation: "workgroup",
				Password:    pass,
			}
			session, err := smb.NewSession(options, false)
			if err == nil {
				session.Close()
				result := d.info
				result.Request = fmt.Sprintf("smb://%s:%s@%s", user, pass, netloc)
				result.Remarks = fmt.Sprintf("弱口令：%s,%s,%s", user, pass, result.Remarks)
				d.result = append(d.result, result)
				b = true
				break
			}
		}
	}
	return b
}
