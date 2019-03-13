#coding=utf-8

import tornado.web
import tornado.httpserver
import tornado.options
import json
from tools.so_proxy import SoProxy

client_domain = "http://localhost:8000"

class RestBaseHandler(tornado.web.RequestHandler):

    def get_current_user(self):
        return self.get_secure_cookie("current_user") 

    def set_default_headers(self):
        global client_domain
        self.set_header("Access-Control-Allow-Origin", client_domain)
        self.set_header("Access-Control-Allow-Headers", "x-requested-with")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')

    def echo_message(self,message):
        self.json_response(True,message)

    def echo_error(self,error):
        self.json_response(False,'',error)

    def json_response(self,result,data,message=''):
        info = {
            'success':result,
            'data':data,
            'message':message
        }
        self.write(json.dumps(info))

    def echo_data(self,data):
        i = {'have':True,'data':data}
        self.echo_message(i)

    def ip_allow(self,allow_ips):
        remote_ip = self.request.remote_ip 
        if remote_ip not in allow_ips :
            self.echo_error("host not allow : %s " % (remote_ip))
            return False
        return True

    def xArguments(self,*names):
        r = []
        for f in names:
            r.append(self.get_argument(f,'').strip())
        return r

http_server = None
application = False

def import_handlers(fn = False):
    if False != fn :
        fn()

def RestRouter(c):
    global application
    url = c.__url__

    if False == application :
        print("NO application")
        exit()
    else :
        application.add_handlers('.*$',[(r'%s' % (url), c)])
    
def ServiceInit(port,bind_host='127.0.0.1',handler_import = False):
    global application
    tornado.options.parse_command_line()
    settings = {
        'debug':True,
        'static_path':"./static",
        'template_path':"./templates",
        'gzip':True,
        'login_url':'/show/login',
        'cookie_secret':"ArEwFxjA43_uhPSRmj1N2xk3nDDUsK"
    }
    application = tornado.web.Application([],**settings)
    import_handlers(handler_import)
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(port,bind_host)
    tornado.ioloop.IOLoop.instance().start()


def loadKunpeng():
    return SoProxy()
