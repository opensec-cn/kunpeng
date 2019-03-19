# poc-scanner 
---
使用kunpeng 做的一个扫描器 

## 安装说明:

* 安装基础的python 运行环境，建议使用python3 
* 安装项目依赖  pip3 install -r requrirements.txt
* 安装supervisor , 按照 poc_server.conf 的方式添加进程配置
* 运行之前需要创建相应的目录， mkdir {extra,so} 
* 编译或者下载最新的kunpeng so 文件, 保存到so 目录，文件名为 kunpeng_c.so
* 用supervisor 的方式启动当前目录的 app.py
* 浏览器打开 http://<your_ip>:12034/ 默认用户名密码: admin , kunpeng@019

## 其他:
* 可以配置kunpeng 的编译环境和poc-scanner 在同一台主机上，用upso.sh 来保持当前项目里的so 是最新的
