package goplugin

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/plugin/go/jdwp"
)

type jdwpRCE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("jdwp", &jdwpRCE{})
}

func (d *jdwpRCE) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Java调试线协议(JDWP)远程代码执行漏洞",
		Remarks: "调试端口对外开放,攻击者可利用该协议执行任意代码，进而直接导致服务器被入侵控制。",
		Level:   0,
		Type:    "RCE",
		Author:  "Medicean",
		References: plugin.References{
			URL: "https://ioactive.com/hacking-java-debug-wire-protocol-or-how/",
			CVE: "",
		},
	}
	return d.info
}
func (d *jdwpRCE) GetResult() []plugin.Plugin {
	return d.result
}
func (d *jdwpRCE) Check(netloc string, meta plugin.TaskMeta) bool {
	if strings.IndexAny(netloc, "http") == 0 {
		return false
	}
	addr := strings.Split(netloc, ":")
	host := addr[0]
	port := 0
	if len(addr) < 2 {
		port = 5005
	} else {
		port, _ = strconv.Atoi(addr[1])
	}
	jdwpclient := jdwp.NewJDWPClient(host, port)
	jdwpclient.SetDebug(true) // 开启日志
	jdwpclient.Start()
	defer jdwpclient.Leave()
	if len(jdwpclient.GetVMInfo()) > 2 {
		result := d.info
		result.Request = fmt.Sprintf("%s:%d", host, port)
		result.Remarks = fmt.Sprintf("Server VM: %s", jdwpclient.GetVMInfo())
		d.result = append(d.result, result)
		return true
	}
	return false
}
