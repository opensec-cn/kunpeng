package plugin

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/opensec-cn/kunpeng/util"
)

// JSONPlugin JSON插件
type JSONPlugin struct {
	Target  string `json:"target"`
	Meta    Plugin `json:"meta"`
	Request struct {
		Path     string `json:"path"`
		PostData string `json:"postdata"`
	} `json:"request"`
	Verify struct {
		Type  string `json:"type"`
		Match string `json:"match"`
	} `json:"verify"`
}

// jsonCheck JSON插件漏洞检测
func jsonCheck(URL string, p JSONPlugin) (bool, Plugin) {
	var request *http.Request
	var result Plugin
	var vulURL = URL + p.Request.Path
	if p.Request.PostData != "" {
		request, _ = http.NewRequest("POST", vulURL, strings.NewReader(p.Request.PostData))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		request, _ = http.NewRequest("GET", vulURL, nil)
	}
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false, result
	}
	switch p.Verify.Type {
	case "string":
		if strings.Contains(resp.ResponseRaw, p.Verify.Match) {
			result = p.Meta
			result.Request = resp.RequestRaw
			result.Response = resp.ResponseRaw
			return true, result
		}
		break
	case "regex":
		if ok, _ := regexp.MatchString(p.Verify.Match, resp.ResponseRaw); ok {
			result = p.Meta
			result.Request = resp.RequestRaw
			result.Response = resp.ResponseRaw
			return true, result
		}
		break
	case "md5":
		if util.GetMd5(resp.Body) == p.Verify.Match {
			result = p.Meta
			result.Request = resp.RequestRaw
			result.Response = resp.ResponseRaw
			return true, result
		}
	}
	return false, result
}
