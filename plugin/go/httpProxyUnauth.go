package goplugin

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	. "github.com/opensec-cn/kunpeng/config"
	"github.com/opensec-cn/kunpeng/plugin"
)

type httpProxyUnauth struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("proxy", &httpProxyUnauth{})
}
func (d *httpProxyUnauth) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "HTTP代理 未授权访问",
		Remarks: "攻击者可使用此代理作为跳板访问内部网络资源。",
		Level:   1,
		Type:    "UNAUTH",
		Author:  "wolf",
		References: plugin.References{
			KPID: "KP-0015",
		},
	}
	return d.info
}
func (d *httpProxyUnauth) GetResult() []plugin.Plugin {
	return d.result
}
func (d *httpProxyUnauth) Check(netloc string, meta plugin.TaskMeta) bool {
	var proxyURL string
	if strings.IndexAny(netloc, "http") == 0 {
		proxyURL = netloc
	} else {
		proxyURL = "http://" + netloc
	}
	proxy := func(_ *http.Request) (*url.URL, error) {
		return url.Parse(proxyURL)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: proxy,
		},
		Timeout: time.Second * time.Duration(Config.Timeout),
	}
	resp, err := client.Get("https://www.apple.com/contact/")
	if err != nil {
		return false
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	if strings.Contains(string(body), "Contacting Apple") {
		result := d.info
		result.Request = proxyURL
		result.Remarks = fmt.Sprintf("HTTP代理无身份认证，%s", result.Remarks)
		d.result = append(d.result, result)
		return true
	}
	return false
}
