#coding=utf-8

import tornado.web
from config import *
import json
import os
import tools.basetornado as base 
import time

@base.RestRouter
class LoadPluginList(base.RestBaseHandler):

    __url__ = '/api/pluginList'

    @tornado.web.authenticated
    def get(self):
        self.write(base.loadKunpeng().GetPlugins())

@base.RestRouter
class LoadPluginList(base.RestBaseHandler):
    __url__ = '/page/plugin/edit'

    @tornado.web.authenticated
    def get(self):
        self.render("edit.html",user=self.get_current_user())

@base.RestRouter
class UserPluginRemove(base.RestBaseHandler):

    __url__ = '/api/plugin/remove'

    @tornado.web.authenticated
    def post(self):
        umd5 = self.xArguments("md5")[0]
        file_name = "ugj_%s.json" % (umd5)
        ugj_filename = "%s/%s" % (EXTRA_PATH,file_name)
        if os.path.isfile(ugj_filename):
            os.remove(ugj_filename)
            self.echo_message("ok")
            return 
        self.write("bad request!")



@base.RestRouter
class UserPluginContent(base.RestBaseHandler):

    __url__ = '/api/user/plugin'

    @tornado.web.authenticated
    def post(self):
        umd5 = self.xArguments("md5")[0]
        file_name = "ugj_%s.json" % (umd5)
        ugj_filename = "%s/%s" % (EXTRA_PATH,file_name)
        if os.path.isfile(ugj_filename):
            json_content = open(ugj_filename,"r").read()
            json_plugin = json.loads(json_content)
            self.echo_data(json_plugin)
            return 
        self.write("bad request!")


@base.RestRouter
class PluginListPage(base.RestBaseHandler):

    __url__ = '/page/pluginList'

    @tornado.web.authenticated
    def get(self):
        self.render("pluginList.html",user=self.get_current_user())


@base.RestRouter
class Default(base.RestBaseHandler):
    
    __url__ = '/'

    def get(self):
        self.redirect('/page/pluginList', permanent=True) 
        
@base.RestRouter
class ShowPage(base.RestBaseHandler):
    
    __url__ = '/show/([a-z]+)'

    def get(self,pageName):
        if pageName in ["login"]:
            self.render("%s.html" % (pageName) )


@base.RestRouter
class UserLoginAuth(base.RestBaseHandler):
    
    __url__ = '/api/user/auth'

    def post(self):
        u,p = self.xArguments("u","p")
        if u == POC_SCANNER_USER and p == POC_SCANNER_PWD_MD5 :
            self.set_secure_cookie("current_user",u,expires_days=None, expires=time.time()+900)
            self.write("ok")
        else:
            self.write("error!")



@base.RestRouter
class UserLogout(base.RestBaseHandler):
    
    __url__ = '/api/user/logout'

    def get(self):
        self.set_secure_cookie("current_user","",expires_days=None, expires=0)
        self.redirect("/")



