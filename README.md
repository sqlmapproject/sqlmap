# sqlmap

[![Build Status](https://api.travis-ci.org/sqlmapproject/sqlmap.svg?branch=master)](https://api.travis-ci.org/sqlmapproject/sqlmap) [![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/doc/COPYING) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap это open source penetration утилита который автоматизируют обноружение и эксплотации SQL инъекций и захват сераера базы данных . Он поставляется с мощным обнаружением, много всяких функций для penetration test-инга и широкий спектр коммутаторов продолжительностью от дактилоскопии базы данных, более выборки данных из базы данных, чтобы получить доступ к основной файловой системы и выполнения команд на операционной системе с помощью вышедших из группы соединений.

Screenshots
----

![Скриншоты](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Вы можете посетить [коллекцию скриншотов](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) которые демонстрировают возможности wiki.

Установка
----

You can download the latest tarball by clicking [here](https://github.com/sqlmapproject/sqlmap/tarball/master) or latest zipball by clicking  [here](https://github.com/sqlmapproject/sqlmap/zipball/master).

Вы можете скачать используя [Git](https://github.com/sqlmapproject/sqlmap) репрозиторий:

    git clone https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap работает только с [Python](http://www.python.org/download/) версиями **2.6.x** и **2.7.x** на любой платформе.

Использование
----

Для того, чтобы получить список основных параметров:

    python sqlmap.py -h

Для того, чтобы получить список всех параметров:

    python sqlmap.py -hh

Вы можите найти пример [здесь](https://asciinema.org/a/46601).
Чтобы вы кратко узнали о возможностях sqlmap, лист возможностей и их описание, вместе с примерами, вам рекомендуеться посетить [Пользовотельский мануал](https://github.com/sqlmapproject/sqlmap/wiki).

Ссылки
----

* Домашняя страница: http://sqlmap.org
* Скачать: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) или [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* RSS: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Отслежевание проблем: https://github.com/sqlmapproject/sqlmap/issues
* Пользовательская документация: https://github.com/sqlmapproject/sqlmap/wiki
* ЧаВо: https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* Mailing list subscription: https://lists.sourceforge.net/lists/listinfo/sqlmap-users
* Mailing list RSS feed: http://rss.gmane.org/messages/complete/gmane.comp.security.sqlmap
* Архив списка рассылки: http://news.gmane.org/gmane.comp.security.sqlmap
* Twitter: [@sqlmap](https://twitter.com/sqlmap)
* Демо: [http://www.youtube.com/user/inquisb/videos](http://www.youtube.com/user/inquisb/videos)
* Скрины: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
