package plugin


// GoPlugin 插件接口
type GoPlugin interface {
	Init() Plugin
	Check(netloc string, meta TaskMeta) bool
	GetResult() []Plugin
}

// Regist 注册插件
func Regist(target string, plugin GoPlugin) {
	GoPlugins[target] = append(GoPlugins[target], plugin)
}