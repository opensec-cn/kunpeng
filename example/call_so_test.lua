--
--- LuaJIT 2.0.4
--
--
local ffi = require("ffi")
local kunpeng = ffi.load("./kunpeng_c.so")

ffi.cdef[[
    void ShowLog();
    void StartWebServer(char* p0);
    char* Check(char* p0);
    char* GetPlugins();
    void SetConfig(char* p0);
    void ShowLog();
    void StartBuffer();
    char* GetLog(char* sep);
]]

--- kunpeng.ShowLog()
--- 用ffi.string 格式化char* 返回的结果，直到\0 结束字符串
local plugins_str  = ffi.string(kunpeng.GetPlugins())
print(plugins_str)

local taskString = [[
{
    "type":"web",
    "netloc":"http://www.google.cn",
    "target":"web"
}
]]

--- 传递lua 字符串到调用函数，需要用ffi.cast 转化数据类型
local taskArg = ffi.cast('char *',taskString)
local result_str = ffi.string(kunpeng.Check(taskArg))

print(result_str)


--- 测试logBuffer 的返回
print("============  logBuffer Start Testing.... ==========")
kunpeng.StartBuffer()
local result_str = ffi.string(kunpeng.Check(taskArg))
local scan_log = ffi.string(kunpeng.GetLog(ffi.cast('char *',"")))
print("result:")
print(result_str)
print("scan_log:")
print(scan_log)

print("============  logBuffer Start End .... ==========")
--- 测试StartWebServer 
kunpeng.StartWebServer( ffi.cast('char *',"0.0.0.0:3000") )
io.stdin:read("*line")

