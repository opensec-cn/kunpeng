# coding:utf-8

import sys
import time
import json
from ctypes import *


def _args_encode(args_string):
    '''Encode by utf-8 in PY3.'''
    if sys.version_info >= (3, 0):
        args_string = args_string.encode('utf-8')
    return args_string


# 加载动态连接库
kunpeng = cdll.LoadLibrary('./kunpeng_c.so')

# 定义出入参变量类型
kunpeng.GetPlugins.restype = c_char_p
kunpeng.Check.argtypes = [c_char_p]
kunpeng.Check.restype = c_char_p
kunpeng.SetConfig.argtypes = [c_char_p]

# 获取插件信息
out = kunpeng.GetPlugins()

# 修改配置
config = {
    'timeout': 10,
    # 'aider': 'http://xxxx:8080',
    # 'http_proxy': 'http://xxxxx:1080',
    # 'pass_list':['xtest']
    # 'extra_plugin_path': '/home/test/plugin/',
}

conf_args = json.dumps(config)
kunpeng.SetConfig(_args_encode(conf_args))

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

task = _args_encode(json.dumps(task))
task2 = _args_encode(json.dumps(task2))

out = kunpeng.Check(task)
print(json.loads(out))
out = kunpeng.Check(task2)
print(json.loads(out))