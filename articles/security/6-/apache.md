# Apache服务加固

## 禁止Apache列表显示文件

(1) 编辑httpd.conf配置文件，
```
 <Directory "/web">

Options Indexes FollowSymLinks

AllowOverride None

Order allow,deny

Allow from all

</Directory>
```
将Options Indexes FollowSymLinks中的Indexes 去掉，就可以禁止 Apache 显示该目录结构。Indexes 的作用就是当该目录下没有 index.html文件时，就显示目录结构。

(2)设置Apache的默认页面，编辑%apache%\conf\httpd.conf配置文件，
```
<IfModule dir\_module>

DirectoryIndex index.html

</IfModule>
```
其中index.html即为默认页面，可根据情况改为其它文件
(3)重新启动Apache服务

## 更改Apache服务器默认端口

（1）修改httpd.conf配置文件，更改默认端口到8080
```
Listen x.x.x.x:8080
```
（2）重启Apache服务

## 禁用Apache Server 中的执行功能

在配置文件access.conf 或httpd.conf中的Options指令处加入IncludesNOEXEC选项，用以禁用Apache Server 中的执行功能。避免用户直接执行Apache 服务器中的执行程序，而造成服务器系统的公开化。

备份access.conf 或httpd.conf文件

修改：
```
Options Includes No exec

```
## 防止恶意攻击

(1) 编辑httpd.conf配置文件，
```
Timeout 10
 KeepAlive ON

KeepAliveTimeout 15

AcceptFilter http data

AcceptFilter https data
```
(2)重新启动Apache服务

## 防止恶意攻击

1、参考配置操作

删除缺省HTML文件：
```
# rm -rf /usr/local/apache2/htdocs/\*
```
删除缺省的CGI脚本：
```
# rm –rf /usr/local/apache2/cgi-bin/\*
```
删除Apache说明文件：
```
# rm –rf /usr/local/apache2/manual
```
删除源代码文件：
```
# rm -rf /path/to/httpd-2.2.4\*
```
根据安装步骤不同和版本不同，某些目录或文件可能不存在或位置不同

## 减少DOS攻击

可同通过编辑httpd.conf文件的具体参数来防范拒绝服务攻击，或减少伤害程度。

        Timeout值：设成300或更少

        KeepAlive：设成KeepAlive ON

        KeepAlive Timeout值：设为15或更少

        StartServers:介于5和10之间

        MinSpareServers值：介于5和10

        MaxKeepAliveRequests的值：不等于0

        MaxSpareServers值：为10或以下

        MaxClients值：256或更少

## 审核登陆

编辑httpd.conf配置文件，设置日志记录文件、记录内容、记录格式。
```
# LogLevel notice

ErrorLog logs/error\_log LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Accept}i\" \"%{Referer}i\" \"%{User-Agent}i\"" combined

CustomLog logs/access\_log  combined (联合)

ErrorLog指令设置错误日志文件名和位置。错误日志是最重要的日志文件，Apache httpd将在这个文件中存放诊断信息和处理请求中出现的错误。若要将错误日志送到Syslog，则设置：ErrorLog syslog。

CustomLog指令设置访问日志的文件名和位置。访问日志中会记录服务器所处理的所有请求。

LogFormat设置日志格式。LogLevel用于调整记录在错误日志中的信息的详细程度，建议设置为notice
```
## 隐藏Apache信息

你应该隐藏Apache的banner信息使攻击者不知道Apache的版本，从而使他们难以利用漏洞

方法：

修改/etc/httpd/conf/httpd.conf
改变服务器签名:
```
ServerSignature Off

重启Apache /sbin/service httpd restart

Serversignature = Off

ServerTokens=Porn
```