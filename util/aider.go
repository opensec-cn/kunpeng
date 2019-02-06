package util

import (
	"net/http"
	"strings"
	"time"
	. "github.com/opensec-cn/kunpeng/config"
)

// AiderCheck 辅助验证，使用标识字符串判断漏洞是否存在（触发漏洞会把标识字符串传输到辅助脚本上，如果查询存在，说明存在漏洞）
func AiderCheck(randStr string) bool {
	time.Sleep(time.Duration(2) * time.Second)
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

// GetAiderNetloc 获取辅助验证地址，可使用dns和http请求判断
func GetAiderNetloc() string {
	return Config.Aider
}
