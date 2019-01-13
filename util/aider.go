package util

import (
	"net/http"
	"strings"
	. "github.com/opensec-cn/kunpeng/config"
)

func AiderCheck(randStr string) bool {
	request, _ := http.NewRequest("GET", Config.Aider+"/check/"+randStr, nil)
	resp, err := RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "VUL00") {
		return true
	}
	return false
}

func GetAiderURL() string {
	return Config.Aider
}