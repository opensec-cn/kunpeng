import time
from ctypes import *
import json
import requests

kunpeng = cdll.LoadLibrary('./kunpeng_c.so')
kunpeng.StartWebServer.argtypes = [c_char_p]
kunpeng.StartWebServer("0.0.0.0:38080")
time.sleep(5)

api = 'http://127.0.0.1:38080'

plugin_list = requests.get(api + '/api/pluginList').json()
print(plugin_list)

config = {
    'timeout': 10,
    # 'aider': 'http://xxxx:8080',
    # 'http_proxy': 'http://xxxxx:1080',
    'pass_list':['xtest'],
    # 'extra_plugin_path': '/home/test/plugin/',
}
requests.post(api + '/api/config',json=config)

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
result = requests.post(api + '/api/check',json=task).json()
print(result)
result = requests.post(api + '/api/check',json=task2).json()
print(result)