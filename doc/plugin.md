## 漏洞POC列表

漏洞POC参考表，传入任务JSON时，可指定以下字段进行关联插件：KPID、检测目标、CVE

| KPID|插件名称|检测目标|CVE|
| :------ | :------ | :------ | :------ |
| KP-0001 | SSH 弱口令                                              | ssh        |                |
| KP-0002 | SMB 匿名共享/弱口令                                     | smb        |                |
| KP-0003 | Redis 未授权访问/弱口令                                 | redis      |                |
| KP-0004 | PostgreSQL 弱口令                                       | postgresql |                |
| KP-0005 | MySQL 弱口令                                            | mysql      |                |
| KP-0006 | SQLServer 弱口令                                        | mssql      |                |
| KP-0007 | MongoDB 未授权访问/弱口令                               | mongodb    |                |
| KP-0008 | Memcache 未授权访问                                     | memcache   |                |
| KP-0009 | FTP 弱口令                                              | ftp        |                |
| KP-0010 | Discuz 3.X SSRF                                         | discuz     |                |
| KP-0011 | Discuz! 6.x/7.x 代码执行                                | discuz     |                |
| KP-0012 | Axis2控制台 弱口令                                      | axis       |                |
| KP-0013 | web目录浏览                                             | web        |                |
| KP-0014 | grafana 控制台弱口令                                    | grafana    |                |
| KP-0015 | HTTP代理 未授权访问                                     | proxy      |                |
| KP-0016 | IIS 物理路径泄露                                        | iis        |                |
| KP-0017 | IIS 短文件名枚举                                        | iis        |                |
| KP-0018 | JBoss 控制台弱口令                                      | jboss      |                |
| KP-0019 | shellshock 破壳漏洞                                     | web        | CVE-2014-6271  |
| KP-0020 | Apache Tomcat 弱口令                                    | tomcat     |                |
| KP-0021 | UcServer 创始人弱口令                                   | discuz     |                |
| KP-0022 | WebDav Put开启                                          | web        |                |
| KP-0023 | WebDav PROPFIND RCE(理论检测)                           | iis        | CVE-2017-7269  |
| KP-0024 | Weblogic 控制台弱口令                                   | weblogic   |                |
| KP-0025 | WebServer 任意文件读取                                  | web        |                |
| KP-0026 | WordPress 后台弱口令                                    | wordpress  |                |
| KP-0027 | Zabbix jsrpc.php SQL注入漏洞                            | zabbix     |                |
| KP-0028 | Zabbix latest.php SQL注入漏洞                           | zabbix     | CVE-2016-10134 |
| KP-0029 | zookeeper 未授权访问                                    | zookeeper  |                |
| KP-0030 | WordPress Mailpress Plugin 远程代码执行漏洞             | wordpress  |                |
| KP-0031 | WebLogic WLS RCE                                        | weblogic   | CVE-2017-10271 |
| KP-0032 | ThinkPHP5 SQL Injection Vulnerability                   | thinkphp   |                |
| KP-0033 | ActiveMQ 任意文件写入漏洞                               | activemq   | CVE-2016-3088  |
| KP-0034 | Apache solr XXE漏洞                                     | solr       | CVE-2017-12629 |
| KP-0035 | Nexus Repository Manager 3 远程代码执行漏洞             | nexus      | CVE-2019-7238  |
| KP-0036 | Struts2 s2-016 远程代码执行                             | struts2    | CVE-2013-2251  |
| KP-0037 | Struts2 s2-017 URL跳转                                  | struts2    | CVE-2013-2248  |
| KP-0038 | Struts2 s2-019 Dynamic method executions                | struts2    | CVE-2013-4316  |
| KP-0039 | Struts2 s2-020 远程代码执行 | struts2    | CVE-2014-0094  |
| KP-0040 | Struts2 s2-032 远程代码执行                             | struts2    | CVE-2016-3081  |
| KP-0041 | Struts2 s2-045 远程代码执行                             | struts2    | CVE-2017-5638  |
| KP-0042 | Discuz! 7.2 admincp.php XSS                             | discuz     |                |
| KP-0043 | Discuz! 7.x ajax.php XSS                                | discuz     |                |
| KP-0044 | Discuz! 7.x announcement.php XSS                        | discuz     |                |
| KP-0045 | Discuz! X2.5 /api.php 网站物理路径泄露                  | discuz     |                |
| KP-0046 | Discuz! 7.x attachment.php XSS                          | discuz     |                |
| KP-0047 | Disucz! x3.0 focus.swf XSS                              | discuz     |                |
| KP-0048 | Discuz! JiangHu Plugin SQL注入                          | discuz     |                |
| KP-0049 | Discuz! 7.x member.php XSS                              | discuz     |                |
| KP-0050 | Discuz! x3.2 misc.php SQL注入                           | discuz     |                |
| KP-0051 | Disucz! x3.0 mp3player.swf XSS                          | discuz     |                |
| KP-0052 | Discuz! 7.2 post.php XSS                                | discuz     |                |
| KP-0053 | Discuz! 积分商城 Plugin SQL注入                         | discuz     |                |
| KP-0054 | Discuz! 6.0 XSS                                         | discuz     |                |
| KP-0055 | Django < 2.0.8 任意URL跳转漏洞                          | django     | CVE-2018-14574 |
| KP-0056 | Docker Remote API未授权访问                             | docker     |                |
| KP-0057 | Drupal Drupalgeddon 2 远程代码执行漏洞                  | drupal     | CVE-2018-7600  |
| KP-0058 | ElasticSearch 未授权访问                                | docker     |                |
| KP-0059 | GlassFish 任意文件读取                                  | glassfish  |                |
| KP-0060 | Hadoop YARN ResourceManager 未授权访问/RCE              | hadoop     |                |
| KP-0061 | Joomla 3.7.0 SQL注入漏洞                                | joomla     | CVE-2017-8917  |
| KP-0062 | Joomla contushdvideoshare 任意文件读取漏洞              | joomla     |                |
| KP-0063 | Joomla departments SQL注入                              | joomla     |                |
| KP-0064 | phpmyadmin scripts/setup.php 反序列化漏洞               | phpmyadmin |                |
| KP-0065 | ThinkPHP5 5.0.22/5.1.29 远程代码执行漏洞                | thinkphp   |                |
| KP-0066 | Weblogic 任意文件上传漏洞                               | weblogic   | CVE-2018-2894  |
| KP-0067 | Weblogic SSRF                                           | weblogic   |                |
| KP-0068 | Wordpress cmdownloads RCE                               | wordpress  |                |
| KP-0069 | WordPress DZS-VideoGallery XSS                          | wordpress  |                |
| KP-0070 | WordPress example.html jQuery DomXSS                    | wordpress  |                |
| KP-0071 | WordPress MainWP 2.0.9.1 登录绕过                       | wordpress  |                |
| KP-0072 | WordPress Sexy Squeeze Pages Plugin XSS                 | wordpress  |                |
| KP-0073 | WordPress swfupload.swf FlashXSS                        | wordpress  |                |
| KP-0074 | WordPress Wpml Plugin XSS                               | wordpress  |                |
| KP-0075 | Socks5代理 未授权访问 | proxy | |

