#coding=utf-8

from config import *

import sys
import time
import json
from ctypes import *

def _args_encode(args_string):
    '''Encode by utf-8 in PY3.'''
    if sys.version_info >= (3, 0):
        args_string = args_string.encode('utf-8')
    return args_string

Instance = False

class KunpengSo(object) :

    def __init__(self,sopath):
        """
        获取Kunpeng的so对象，传递参数: 
        sopath so的路径
        """
        self.kunpeng = cdll.LoadLibrary(sopath)
        self.kunpeng.GetPlugins.restype = c_char_p
        self.kunpeng.SetConfig.argtypes = [c_char_p]
        self.kunpeng.Check.argtype = [c_char_p]
        self.kunpeng.Check.restype = c_char_p
        self.kunpeng.GetLog.argtype = [c_char_p]
        self.kunpeng.GetLog.restype = c_char_p

        self.kunpeng.ShowLog()
        self.kunpeng.SetConfig(_args_encode(json.dumps({"extra_plugin_path":EXTRA_PATH})))

    def GetPlugins(self):
        """
        通过kunpeng.so 获取当前的插件列表
        """
        return self.kunpeng.GetPlugins()

    def Check(self,task):
        return self.kunpeng.Check(_args_encode(task))

    def StartBuffer(self):
        return self.kunpeng.StartBuffer()
            
    def GetLog(self,sep=""):
        return self.kunpeng.GetLog(_args_encode(sep))

    def GetVersion(self):
        return self.kunpeng.GetVersion()

def SoProxy():
    """
    获取so的对象
    """
    global Instance
    if Instance == False :
        Instance = KunpengSo(SO_PATH)

    return Instance 
