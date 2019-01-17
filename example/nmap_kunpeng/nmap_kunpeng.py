#coding:utf-8
import nmap
from ctypes import *
import json

# 加载动态连接库
so = cdll.LoadLibrary('./kunpeng_c.so')

# 定义出入参变量类型
so.GetPlugins.restype = c_char_p
so.Check.argtypes = [c_char_p]
so.Check.restype = c_char_p
so.SetConfig.argtypes = [c_char_p]

nm = nmap.PortScanner()
def scan(hostname,ports):
    nm.scan(hostname,ports,'--open')
    task_list = []
    # print(nm.get_nmap_last_output())
    for host in nm.all_hosts():
        if nm[host]['hostnames']:
            domain = nm[host]['hostnames'][0]['name']
            print(domain)
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                info = nm[host][proto][port]
                name = info['name']
                product = info['product']
                if 'http' in name:
                    scheme = 'http'
                    if name in ['https','ssl'] or port == 443:
                        scheme = 'https'
                    ip_url = '{}://{}:{}'.format(scheme,host,port)
                    domain_url = '{}://{}:{}'.format(scheme,domain,port)
                    task_list.append({'type':'web','target': 'web', 'netloc': ip_url})
                    task_list.append({'type':'web','target': 'web', 'netloc': domain_url})
                    if product == '' or product == name: continue
                    task_list.append({'type':'web','target': product, 'netloc': ip_url})
                    task_list.append({'type':'web','target': product, 'netloc': domain_url})
                else:
                    task_list.append({'type':'service','target': name, 'netloc': host + ':' + str(port)})
    for task in task_list:
        out = so.Check(json.dumps(task))
        print(json.loads(out))

if __name__ == '__main__':
    scan('www.baidu.com', '80,443')