# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.7|3.x](https://img.shields.io/badge/python-2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![x](https://img.shields.io/badge/x-@sqlmap-blue.svg)](https://x.com/sqlmap)

sqlmap 是一款开源的渗透测试工具，能够自动检测和利用 SQL 注入漏洞，并接管数据库服务器。它配备了强大的检测引擎、众多专为高级渗透测试人员设计的特色功能，以及丰富的命令行选项，包括数据库指纹识别、从数据库获取数据、访问底层文件系统，以及通过带外连接在操作系统上执行命令。

截图
----

![截图](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

你可以访问 Wiki 上的[截图集](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots)，查看部分功能的演示。

安装
----

你可以点击[此处](https://github.com/sqlmapproject/sqlmap/tarball/master)下载最新的 tar 包，或点击[此处](https://github.com/sqlmapproject/sqlmap/zipball/master)下载最新的 zip 包。

推荐通过克隆 [Git](https://github.com/sqlmapproject/sqlmap) 仓库来下载 sqlmap：

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap 在任何平台上均可直接与 [Python](https://www.python.org/download/) **2.7** 和 **3.x** 版本配合使用。

使用方法
----

查看基本选项和开关列表：

    python sqlmap.py -h

查看所有选项和开关列表：

    python sqlmap.py -hh

你可以[在此处](https://asciinema.org/a/46601)查看示例运行。
要了解 sqlmap 的功能概览、支持的特性列表，以及所有选项和开关的说明及示例，建议查阅[用户手册](https://github.com/sqlmapproject/sqlmap/wiki/Usage)。

相关链接
----

* 主页：https://sqlmap.org
* 下载：[.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) 或 [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* 提交 RSS 订阅：https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Issue 跟踪：https://github.com/sqlmapproject/sqlmap/issues
* 用户手册：https://github.com/sqlmapproject/sqlmap/wiki
* 常见问题（FAQ）：https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X（推特）：[@sqlmap](https://x.com/sqlmap)
* 演示视频：https://www.youtube.com/user/inquisb/videos
* 截图：https://github.com/sqlmapproject/sqlmap/wiki/Screenshots

翻译
----

* [阿拉伯语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ar-AR.md)
* [孟加拉语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-bn-BD.md)
* [保加利亚语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-bg-BG.md)
* [中文](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-zh-CN.md)
* [克罗地亚语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-hr-HR.md)
* [荷兰语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-nl-NL.md)
* [法语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-fr-FR.md)
* [格鲁吉亚语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ka-GE.md)
* [德语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-de-DE.md)
* [希腊语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-gr-GR.md)
* [印地语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-in-HI.md)
* [印度尼西亚语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-id-ID.md)
* [意大利语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-it-IT.md)
* [日语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ja-JP.md)
* [韩语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ko-KR.md)
* [库尔德语（中部）](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ckb-KU.md)
* [波斯语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-fa-IR.md)
* [波兰语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-pl-PL.md)
* [葡萄牙语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-pt-BR.md)
* [俄语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ru-RU.md)
* [塞尔维亚语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-rs-RS.md)
* [斯洛伐克语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-sk-SK.md)
* [西班牙语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-es-MX.md)
* [土耳其语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-tr-TR.md)
* [乌克兰语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-uk-UA.md)
* [越南语](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-vi-VN.md)
