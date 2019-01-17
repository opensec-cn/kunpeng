package goplugin

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/opensec-cn/kunpeng/plugin"
	"golang.org/x/crypto/ssh"
)

type sshWeakPass struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("ssh", &sshWeakPass{})
}
func (d *sshWeakPass) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "SSH 弱口令",
		Remarks: "直接导致服务器被入侵控制。",
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
func (d *sshWeakPass) GetResult() []plugin.Plugin {
	return d.result
}
func (d *sshWeakPass) Check(netloc string, meta plugin.TaskMeta) (b bool) {
	if strings.IndexAny(netloc, "http") == 0 {
		return
	}
	userList := []string{
		"root",
	}
	for _, user := range userList {
		for _, pass := range meta.PassList {
			pass = strings.Replace(pass, "{user}", user, -1)
			fmt.Println(pass)
			config := &ssh.ClientConfig{
				User: user,
				Auth: []ssh.AuthMethod{
					ssh.Password(pass),
				},
				HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
					return nil
				},
				Timeout: time.Duration(10) * time.Second,
			}
			client, err := ssh.Dial("tcp", netloc, config)
			if err == nil {
				client.Close()
				result := d.info
				result.Request = fmt.Sprintf("ssh://%s:%s@%s", user, pass, netloc)
				result.Remarks = fmt.Sprintf("弱口令：%s,%s,%s", user, pass, result.Remarks)
				d.result = append(d.result, result)
				b = true
				break
			} else if strings.Contains(err.Error(), "none password") == false {
				return b
			}
		}
	}
	return b
}
