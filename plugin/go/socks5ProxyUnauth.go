package goplugin

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	. "github.com/opensec-cn/kunpeng/config"
	"github.com/opensec-cn/kunpeng/plugin"
	"golang.org/x/net/proxy"
)

type socks5ProxyUnauth struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("proxy", &socks5ProxyUnauth{})
}
func (d *socks5ProxyUnauth) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Socks5代理 未授权访问",
		Remarks: "攻击者可使用此代理作为跳板访问内部网络资源。",
		Level:   1,
		Type:    "UNAUTH",
		Author:  "wolf",
		References: plugin.References{
			KPID: "KP-0076",
		},
	}
	return d.info
}
func (d *socks5ProxyUnauth) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *socks5ProxyUnauth) Check(netloc string, meta plugin.TaskMeta) bool {
	if strings.IndexAny(netloc, "http") == 0 {
		return false
	}
	dialer, err := proxy.SOCKS5("tcp", netloc, nil, proxy.Direct)
	if err != nil {
		return false
	}
	httpTransport := &http.Transport{}
	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   time.Second * time.Duration(Config.Timeout),
	}
	httpTransport.Dial = dialer.Dial
	resp, err := httpClient.Get("https://www.apple.com/contact/")
	if err != nil {
		return false
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	if strings.Contains(string(body), "Contacting Apple") {
		result := d.info
		result.Request = "socks5://" + netloc
		result.Remarks = fmt.Sprintf("socks5代理无身份认证，%s", result.Remarks)
		d.result = append(d.result, result)
		return true
	}
	return false
}
