# sqlmap

[![Build Status](https://api.travis-ci.org/sqlmapproject/sqlmap.svg?branch=master)](https://travis-ci.org/sqlmapproject/sqlmap) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![PyPI version](https://badge.fury.io/py/sqlmap.svg)](https://badge.fury.io/py/sqlmap) [![GitHub closed issues](https://img.shields.io/github/issues-closed-raw/sqlmapproject/sqlmap.svg?colorB=ff69b4)](https://github.com/sqlmapproject/sqlmap/issues?q=is%3Aissue+is%3Aclosed) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap 是一个开源的渗透测试工具，可以用来自动化的检测，利用SQL注入漏洞，获取数据库服务器的权限。它具有功能强大的检测引擎,针对各种不同类型数据库的渗透测试的功能选项，包括获取数据库中存储的数据，访问操作系统文件甚至可以通过外带数据连接的方式执行操作系统命令。

演示截图
----

![截图](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

你可以访问 wiki上的 [截图](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) 查看各种用法的演示

安装方法
----

你可以点击 [这里](https://github.com/sqlmapproject/sqlmap/tarball/master) 下载最新的 `tar` 打包的源代码 或者点击 [这里](https://github.com/sqlmapproject/sqlmap/zipball/master)下载最新的 `zip` 打包的源代码.

推荐你从 [Git](https://github.com/sqlmapproject/sqlmap) 仓库获取最新的源代码:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap 可以运行在 [Python](http://www.python.org/download/)  **2.6**, **2.7**  和  **3.x** 版本的任何平台上

使用方法
----

通过如下命令可以查看基本的用法及命令行参数:

    python sqlmap.py -h

通过如下的命令可以查看所有的用法及命令行参数:

    python sqlmap.py -hh

你可以从 [这里](https://asciinema.org/a/46601) 看到一个sqlmap 的使用样例。除此以外，你还可以查看 [使用手册](https://github.com/sqlmapproject/sqlmap/wiki/Usage)。获取sqlmap所有支持的特性、参数、命令行选项开关及说明的使用帮助。

链接
----

* 项目主页: http://sqlmap.org
* 源代码下载: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) or [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* RSS 订阅: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Issue tracker: https://github.com/sqlmapproject/sqlmap/issues
* 使用手册: https://github.com/sqlmapproject/sqlmap/wiki
* 常见问题 (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* Twitter: [@sqlmap](https://twitter.com/sqlmap)
* 教程: [http://www.youtube.com/user/inquisb/videos](http://www.youtube.com/user/inquisb/videos)
* 截图: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
