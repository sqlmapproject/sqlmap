# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![x](https://img.shields.io/badge/x-@sqlmap-blue.svg)](https://x.com/sqlmap)

sqlmap 是一款开源的渗透测试工具，可以自动化进行SQL注入的检测、利用，并能接管数据库服务器。它具有功能强大的检测引擎,为渗透测试人员提供了许多专业的功能并且可以进行组合，其中包括数据库指纹识别、数据读取和访问底层文件系统，甚至可以通过带外数据连接的方式执行系统命令。

演示截图
----

![截图](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

你可以查看 wiki 上的 [截图](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) 了解各种用法的示例

安装方法
----

你可以点击 [这里](https://github.com/sqlmapproject/sqlmap/tarball/master) 下载最新的 `tar` 打包好的源代码，或者点击 [这里](https://github.com/sqlmapproject/sqlmap/zipball/master)下载最新的 `zip` 打包好的源代码.

推荐直接从 [Git](https://github.com/sqlmapproject/sqlmap) 仓库获取最新的源代码:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap 可以运行在 [Python](https://www.python.org/download/)  **2.6**, **2.7**  和  **3.x** 版本的任何平台上

使用方法
----

通过如下命令可以查看基本的用法及命令行参数:

    python sqlmap.py -h

通过如下的命令可以查看所有的用法及命令行参数:

    python sqlmap.py -hh

你可以从 [这里](https://asciinema.org/a/46601) 看到一个 sqlmap 的使用样例。除此以外，你还可以查看 [使用手册](https://github.com/sqlmapproject/sqlmap/wiki/Usage)。获取 sqlmap 所有支持的特性、参数、命令行选项开关及详细的使用帮助。

链接
----

* 项目主页: https://sqlmap.org
* 源代码下载: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) or [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* Commit的 RSS 订阅: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* 问题跟踪器: https://github.com/sqlmapproject/sqlmap/issues
* 使用手册: https://github.com/sqlmapproject/sqlmap/wiki
* 常见问题 (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://x.com/sqlmap)
* 教程: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* 截图: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
