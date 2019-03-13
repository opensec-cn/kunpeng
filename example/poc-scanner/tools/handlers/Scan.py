#coding=utf-8

import tornado.web
import tools.basetornado as base 

@base.RestRouter
class Scan(base.RestBaseHandler):

    __url__ = '/page/scanItem'

    @tornado.web.authenticated
    def get(self):
        self.render("scan.html",user=self.get_current_user())

    @tornado.web.authenticated
    def post(self):
        kp = base.loadKunpeng()
        code = self.xArguments("code")[0]
        kp.StartBuffer()
        message = kp.Check(code)
        log = kp.GetLog("")
        self.render("result.html",result=message,log=log,user=self.get_current_user())


