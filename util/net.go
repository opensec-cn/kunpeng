package util

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	. "github.com/opensec-cn/kunpeng/config"
	"time"
)


var client *http.Client

// Resp 封装的http返回包
type Resp struct {
	Body        []byte
	Other       *http.Response
	RequestRaw  string
	ResponseRaw string
}

func init() {
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client = &http.Client{
		Transport: transport,
		Timeout:   time.Second * time.Duration(Config.Timeout),
		Jar:       jar,
	}
}

func setProxy(){
	if Config.HTTPProxy == "" {
		client.Transport = nil
	} else {
		proxy := func(_ *http.Request) (*url.URL, error) {
			return url.Parse(Config.HTTPProxy)
		}
		transport := &http.Transport{
			Proxy:           proxy,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = transport
	}
}

// RequestDo 封装的http请求方法
func RequestDo(request *http.Request, raw bool) (Resp, error) {
	var result Resp
	var err error
	setProxy()
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36")
	if raw {
		requestOut, err := httputil.DumpRequestOut(request, true)
		if err == nil {
			result.RequestRaw = string(requestOut)
		}
	}
	// fmt.Println(request.URL.String())
	client.Timeout = time.Second * time.Duration(Config.Timeout)
	result.Other, err = client.Do(request)
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


func TCPSend(netloc string, data []byte)([]byte ,error){
	conn, err := net.DialTimeout("tcp", netloc, time.Second * time.Duration(Config.Timeout))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ , err = conn.Write(data)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 20480)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	fmt.Println(string(buf[:n]))
	return buf[:n], nil
}