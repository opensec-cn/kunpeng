#coding:utf-8

import time
import json
from ctypes import *

# 加载动态连接库
kunpeng = cdll.LoadLibrary('./kunpeng_c.so')

# 定义出入参变量类型
kunpeng.GetPlugins.restype = c_char_p
kunpeng.Check.argtypes = [c_char_p]
kunpeng.Check.restype = c_char_p
kunpeng.SetConfig.argtypes = [c_char_p]

# 获取插件信息
out = kunpeng.GetPlugins()
print(out)

# 修改配置
config = {
    'timeout': 10,
    'aider': '',
    'httpproxy': '',
    'passlist':['xtest']
}
kunpeng.SetConfig(json.dumps(config))

# 开启日志打印
kunpeng.ShowLog()

# 扫描目标
task = {
    'type': 'web',
    'netloc': 'http://www.google.cn',
    'target': 'web',
    'meta':{
        'system': '',
        'pathlist':[],
        'filelist':[],
        'passlist':[]
    }
}
task2 = {
    'type': 'service',
    'netloc': '192.168.0.105:3306',
    'target': 'mysql',
    'meta':{
        'system': '',
        'pathlist':[],
        'filelist':[],
        'passlist':[]
    }
}
out = kunpeng.Check(json.dumps(task))
print(json.loads(out))
out = kunpeng.Check(json.dumps(task2))
print(json.loads(out))