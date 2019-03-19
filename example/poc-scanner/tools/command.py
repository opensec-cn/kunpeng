#coding=utf-8

import tools.basetornado as base
import importlib
import os

def importHandlers():
    listfiles = os.listdir("tools/handlers/")
    for _idx,_py in enumerate(listfiles) :
        if _py[-3:] == ".py":
            name,_ = _py.split(".")
            if name != "__init__":
                pname = "tools.handlers.%s" % (name)
                importlib.import_module(pname)

def runTornadoCommand(host,port):
    print("poc_scanner use kunpeng : %s " % (base.loadKunpeng().GetVersion()))
    base.ServiceInit(port,host,importHandlers)
    
