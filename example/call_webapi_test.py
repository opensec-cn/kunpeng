import time
from ctypes import *
import json
import requests

so = cdll.LoadLibrary('./kunpeng_c.so')
# listen 0.0.0.0:38080
so.StartWebServer()
time.sleep(5)

api = 'http://127.0.0.1:38080'

plugin_list = requests.get(api + '/api/pluginList').json()
print(plugin_list)

config = {
    'timeout': 10,
    'aider': '',
    'httpproxy': '',
    'passlist':['xtest']
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