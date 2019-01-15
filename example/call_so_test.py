#coding:utf-8

import time
from ctypes import *
import json

# 加载动态连接库
so = cdll.LoadLibrary('./kunpeng_c.so')

# 定义出入参变量类型
so.GetPlugins.restype = c_char_p
so.Check.argtypes = [c_char_p]
so.Check.restype = c_char_p
so.SetConfig.argtypes = [c_char_p]

# 获取插件信息
out = so.GetPlugins()
print(out)

# 修改配置
config = {
    'timeout': 10,
    'aider': '',
    'httpproxy': '',
    'passlist':['xtest']
}
so.SetConfig(json.dumps(config))

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
out = so.Check(json.dumps(task))
print(json.loads(out))
out = so.Check(json.dumps(task2))
print(json.loads(out))