package common

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"time"
)

//References 插件附加信息
type References struct{
	URL string `json:"url"`
	CVE string `json:"cve"`
}

// PluginInfo 漏洞插件信息
type PluginInfo struct {
	Name     string `json:"name"`
	Remarks  string `json:"remarks"`
	Level    int `json:"level"`
	Type     string `json:"type"`
	Author	 string `json:"author"`
	References `json:"references"`
	Request  string
	Response string
}

// JSONPlugin JSON插件
type JSONPlugin struct {
	Target string `json:"target"`
	Meta    PluginInfo `json:"meta"`
	Request struct {
		Path     string `json:"path"`
		PostData string `json:"postdata"`
	} `json:"request"`
	Verify  struct {
		Type  string `json:"type"`
		Match string `json:"match"`
	} `json:"verify"`
}

var Client *http.Client

// Resp 封装的http返回包
type Resp struct {
	Body        []byte
	Other       *http.Response
	RequestRaw  string
	ResponseRaw string
}

func init() {
	jar, _ := cookiejar.New(nil)
	Timeout := 15
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	Client = &http.Client{
		Transport: transport,
		Timeout:   time.Second * time.Duration(Timeout),
		Jar:       jar,
	}
}

// RequestDo 封装的http请求方法
func RequestDo(request *http.Request, raw bool) (Resp, error) {
	var result Resp
	var err error
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36")
	if raw {
		requestOut, err := httputil.DumpRequestOut(request, true)
		if err == nil {
			result.RequestRaw = string(requestOut)
		}
	}
	// fmt.Println(request.URL.String())
	result.Other, err = Client.Do(request)
	if err != nil {
		fmt.Println(1, err)
		return result, err
	}
	defer result.Other.Body.Close()
	if raw {
		ResponseOut, err := httputil.DumpResponse(result.Other, true)
		if err == nil {
			result.ResponseRaw = string(ResponseOut)
		}
	}
	result.Body, _ = ioutil.ReadAll(result.Other.Body)
	return result, err
}
