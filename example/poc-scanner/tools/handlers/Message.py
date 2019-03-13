#coding=utf-8

import tornado.web
from config import * 
import tools.basetornado as base 

@base.RestRouter
class Message(base.RestBaseHandler):

    __url__ = '/page/message'

    @tornado.web.authenticated
    def get(self):
        self.render("message.html",user=self.get_current_user())


