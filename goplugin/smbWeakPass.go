package goplugin

import (
	"fmt"
	"strings"
	"vuldb/plugin"
	"vuldb/common"
	"github.com/stacktitan/smb/smb"
)

type smbWeakPass struct {
	info   common.PluginInfo
	result []common.PluginInfo
}

func init() {
	plugin.Regist("smb", &smbWeakPass{})
}
func (d *smbWeakPass) Init() common.PluginInfo{
	d.info = common.PluginInfo{
		Name:    "MongoDB 未授权访问/弱口令",
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
func (d *smbWeakPass) GetResult() []common.PluginInfo {
	return d.result
}
func (d *smbWeakPass) Check(netloc string, meta plugin.TaskMeta) (b bool) {
	if strings.IndexAny(netloc,"http") == 0{
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
	for _, user := range userList {
		for _, pass := range PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			options := smb.Options{
				Host:        strings.Split(netloc, ":")[0],
				Port:        445,
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
