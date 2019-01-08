# Kunpeng

kunpeng是一个Golang编写的开源POC检测框架，以动态链接库的形式提供各种语言调用，通过此项目可快速对目标进行安全漏洞检测，比攻击者快一步发现风险漏洞。


## 简介

作为漏洞发现、检测中的核心：漏洞库，存在着维护成本高，无法及时更新、不同框架以及各自独立维护的问题，xxx将以动态链接库的形式提供调用，开发人员只需专注于相关安全检测系统的业务逻辑代码实现，而不必各自重复的耗费精力维护漏洞库。

VulDB集成了包括服务、web组件、CMS的漏洞POC，可检测包括弱口令、SQL注入、XSS、RCE等漏洞类型。

## 特点
开箱即用，无需安装任何依赖库
跨语言使用，编译后为so文件的动态链接库
单文件，更新方便，直接覆盖即可
开源社区维护，内置常见漏洞POC
最小化漏洞验证和理论验证，无攻击行为

## 使用场景
渗透测试辅助工具：例如msf，交互控制台 -> **Kunpeng**

网络资产安全监控：例如巡风，端口扫描 -> 指纹识别 -> **kunpeng**  或  nmap -> **kunpeng**

扫描器： 作为扫描器的漏洞库

更多使用场景可自由发挥 


## 下载地址

[releases]


Kunpeng_go_v{xx}.zip 为GO语言专版，其余语言下载 Kunpeng_c_v{xx}.zip

## 使用方法

```go
接口调用说明

/*  传入任务JSON，格式为：
    {
        "type": "web", //目标类型web或者service
        "netloc": "http://xxx.com", //目标地址，web为URL，service格式为123.123.123.123:22
        "target": "wordpress", //目标名称，决定使用哪些POC进行检测
        "system": "windows", //系统，部分漏洞检测方法不同系统存在差异，提供给插件进行判断
        "pathlist":[], //目录路径URL列表，部分插件需要此类信息，例如列目录漏洞插件
        "filelist":[], //文件路径URL列表，部分插件需要此类信息，例如struts2漏洞相关插件
    }
    返回是否存在漏洞和漏洞检测结果
*/
Check(taskJSON string) (bool, []map[string]string) 

// 获取插件列表信息
GetPlugins() []map[string]string

// 设置HTTP代理，所有插件请求流量将通过代理发送
SetProxy(URL string)

/* 设置漏洞辅助验证接口，部分漏洞无法通过回显判断是否存在漏洞，可通过辅助验证接口进行判断
python -c'import socket,base64;exec(base64.b64decode("aGlzdG9yeSA9IFtdCndlYiA9IHNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsc29ja2V0LlNPQ0tfU1RSRUFNKQp3ZWIuYmluZCgoJzAuMC4wLjAnLDgwODgpKQp3ZWIubGlzdGVuKDEwKQp3aGlsZSBUcnVlOgogICAgdHJ5OgogICAgICAgIGNvbm4sYWRkciA9IHdlYi5hY2NlcHQoKQogICAgICAgIGRhdGEgPSBjb25uLnJlY3YoNDA5NikKICAgICAgICByZXFfbGluZSA9IGRhdGEuc3BsaXQoIlxyXG4iKVswXQogICAgICAgIGFjdGlvbiA9IHJlcV9saW5lLnNwbGl0KClbMV0uc3BsaXQoJy8nKVsxXQogICAgICAgIHJhbmtfc3RyID0gcmVxX2xpbmUuc3BsaXQoKVsxXS5zcGxpdCgnLycpWzJdCiAgICAgICAgaHRtbCA9ICJORVcwMCIKICAgICAgICBpZiBhY3Rpb24gPT0gImFkZCI6CiAgICAgICAgICAgIGhpc3RvcnkuYXBwZW5kKHJhbmtfc3RyKQogICAgICAgICAgICBwcmludCAiYWRkIityYW5rX3N0cgogICAgICAgIGVsaWYgYWN0aW9uID09ICJjaGVjayI6CiAgICAgICAgICAgIHByaW50ICJjaGVjayIrcmFua19zdHIKICAgICAgICAgICAgaWYgcmFua19zdHIgaW4gaGlzdG9yeToKICAgICAgICAgICAgICAgIGh0bWw9IlZVTDAwIgogICAgICAgICAgICAgICAgaGlzdG9yeS5yZW1vdmUocmFua19zdHIpCiAgICAgICAgcmF3ID0gIkhUVFAvMS4wIDIwMCBPS1xyXG5Db250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9dXRmLThcclxuQ29udGVudC1MZW5ndGg6ICVkXHJcbkNvbm5lY3Rpb246IGNsb3NlXHJcblxyXG4lcyIgJShsZW4oaHRtbCksaHRtbCkKICAgICAgICBjb25uLnNlbmQocmF3KQogICAgICAgIGNvbm4uY2xvc2UoKQogICAgZXhjZXB0OnBhc3M="))'
可在辅助验证机器上运行以上代码，传入http://IP:8088。
*/
SetAider(URL string)

// 开启web接口，如果觉得类型转换麻烦，可开启后通过web接口进行调用
StartWebServer()
```

## 使用例子
- Golang

```go
package main

import "plugin"
import "fmt"
import "encoding/json"

// TaskInfo 任务结构
type TaskInfo struct {
	Type string `json:"type"`
	Netloc string `json:"netloc"`
	Target string `json:"target"`
	System string `json:"system"`
	PathList []string `json:"pathList"`
	FileList []string `json:"fileList"`
}

type Greeter interface {
	Check(task string) (bool, []map[string]string)
	GetPlugins() []map[string]string
	SetProxy(URL string)
	SetAider(URL string)
}

func main() {
	plug, err := plugin.Open("/tmp/go.so")
	if err != nil {
		fmt.Println(err)
		return
	}
	symGreeter, err := plug.Lookup("Greeter")
	if err != nil {
		fmt.Println(err)
		return
	}
	greeter, ok := symGreeter.(Greeter)
	if !ok {
		fmt.Println("unexpected type from module symbol")
		return
	}
	fmt.Println(greeter.GetPlugins())
	task := TaskInfo{"web", "http://xxx.com/", "wordpress", "",[]string{},[]string{}}
	jsonBytes, _ := json.Marshal(task)
	ok,result:= greeter.Check(string(jsonBytes))
	fmt.Println(ok,result)
}
```

- python

```python
import time
from ctypes import *
import json

so = cdll.LoadLibrary('./c.so')
so.GetPlugins.restype = c_char_p
plugins = so.GetPlugins()
print(plugins)
so.Check.argtypes = [c_char_p]
so.Check.restype = c_char_p
task = {
    'type': 'service',
    'netloc': '123.11.11.11:22',
    'target': 'ssh',
    'system': '',
    'pathlist':[],
    'filelist':[]
}
vul_result = so.Check(json.dumps(task))
print(vul_result)
```



## 插件开发
支持2种类型插件，Go和JSON插件，大部分漏洞使用JSON插件即可实现验证，分别存放在goplugin和jsonplugin目录中，JSON插件会在编译时利用generate编译进去。

- golang插件例子1

```go
// 包名需定义goplugin
package goplugin

// 引入plugin
import (
	"fmt"
	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/go-redis/redis"
)

// 定义插件结构，info，result需固定存在
type redisWeakPass struct {
	info   plugin.PluginInfo //插件信息
	result []plugin.PluginInfo //漏洞结果
}

func init() {
    // 注册插件，定义插件目标名称
	plugin.Regist("redis", &redisWeakPass{})
}
func (d *redisWeakPass) Init() plugin.PluginInfo{
	d.info = plugin.PluginInfo{
		Name:    "Redis 未授权访问/弱口令",
		Remarks: "导致敏感信息泄露，严重可导致服务器直接被入侵控制。",
		Level:   0,
		Type:    "WEAK",
		Author:   "wolf",
	    References: plugin.References{
		    URL: "https://www.freebuf.com/vuls/162035.html",
		    CVE: "",
	},
	}
	return d.info
}

func (d *redisWeakPass) GetResult() []plugin.PluginInfo {
	return d.result
}

func (d *redisWeakPass) Check(netloc string, meta plugin.TaskMeta) bool {
	for _, pass := range PassList {
		client := redis.NewClient(&redis.Options{
			Addr:     netloc,
			Password: pass,
			DB:       0,
		})
		_, err := client.Ping().Result()
		if err == nil {
			client.Close()
			result := d.info
			result.Request = fmt.Sprintf("redis://%s@%s", pass, netloc)
			if pass == "" {
				result.Remarks = fmt.Sprintf("未授权访问，%s", result.Remarks)
			} else {
				result.Remarks = fmt.Sprintf("弱口令：%s,%s", pass, result.Remarks)
			}
			d.result = append(d.result, result)
			return true
		}
	}
	return false
}
```


- golang插件例子2

```go
package goplugin

import (
	"net/http"
	"strings"
	"github.com/opensec-cn/kunpeng/util"
	"github.com/opensec-cn/kunpeng/plugin"
)

type webDavRCE struct {
	info   plugin.PluginInfo
	result []plugin.PluginInfo
}

func init() {
	plugin.Regist("iis", &webDavRCE{})
}

func (d *webDavRCE) Init() plugin.PluginInfo{
	d.info = plugin.PluginInfo{
		Name:    "WebDav PROPFIND RCE(理论检测)",
		Remarks: "CVE-2017-7269,Windows Server 2003R2版本IIS6.0的WebDAV服务中的ScStoragePathFromUrl函数存在缓存区溢出漏洞",
		Level:   1,
		Type:    "RCE",
		Author:   "wolf",
		References: plugin.References{
			URL: "",
			CVE: "",
		},
	}
	return d.info
}

func (d *webDavRCE) GetResult() []plugin.PluginInfo {
	return d.result
}

func (d *webDavRCE) Check(URL string, meta plugin.TaskMeta) bool {
	request, err := http.NewRequest("OPTIONS", URL, nil)
	if err != nil {
		return false
	}
	// 封装好的HTTP请求
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if resp.Other.Header.Get("Server") == "Microsoft-IIS/6.0" && strings.Contains(resp.Other.Header.Get("Allow"), "PROPFIND") {
		result := d.info
		result.Response = resp.ResponseRaw
		result.Request = resp.RequestRaw
		d.result = append(d.result, result)
		return true
	}
	return false
}
```

- JSON插件例子

```json
{
    "target":"wordpress",
    "meta":{
        "name":    "WordPress example.html jQuery DomXSS",
        "remarks": "WordPress example.html jQuery 1.7.2 存在DomXSS漏洞",
        "level":   3,
        "type":    "XSS",
        "author":   "wolf",
        "references": {
            "url":"https://www.seebug.org/vuldb/ssvid-89179",
            "cve":""
        }
    },
    "request":{
        "path":     "/wp-content/themes/twentyfifteen/genericons/example.html",
        "postData": ""
    },
    "verify":{
        "type":  "string",
        "match": "jquery/1.7.2/jquery.min.js"
    }
}
```


### 编译
```shell
go get https://github.com/opensec-cn/kunpeng
cd xxx/opensec-cn/vuldb

# 打包JSON插件到项目代码中
go generate

# 编译c版本（所有语言均可使用）
go build -buildmode=c-shared -o c.so

# 编译Go专用版本
go build -buildmode=plugin -o go.so
```

### 效果图



## 法律法规

此项目将严格按照相关法律法规进行，所有检测代码均为无攻击行为的POC以及理论判断。

[releases]: https://github.com/opensec-cn/kunpeng/releases