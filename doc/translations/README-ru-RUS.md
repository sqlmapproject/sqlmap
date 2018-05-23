# sqlmap

[![Build Status](https://api.travis-ci.org/sqlmapproject/sqlmap.svg?branch=master)](https://api.travis-ci.org/sqlmapproject/sqlmap) [![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap - это инструмент для тестирования уязвимостей с открытым исходным кодом, который автоматизирует процесс обнаружения и использования ошибок SQL-инъекций и захвата серверов баз данных. Он оснащен мощным механизмом обнаружения, множеством приятных функций для профессионального тестера уязвимостей и широким спектром скриптов, которые упрощают работу с базами данных, от сбора данных из базы данных, до доступа к базовой файловой системе и выполнения команд в операционной системе через out-of-band соединение.

**Проект sqlmap спонсируется [Netsparker Web Application Security Scanner](https://www.netsparker.com/?utm_source=github.com&utm_medium=referral&utm_content=sqlmap+repo&utm_campaign=generic+advert).**

Скриншоты
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Вы можете посетить [набор скриншотов](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) демонстрируемые некоторые функции в wiki.

Установка
----

Вы можете скачать последнюю версию tarball, нажав [сюда](https://github.com/sqlmapproject/sqlmap/tarball/master) или последний zipball, нажав  [сюда](https://github.com/sqlmapproject/sqlmap/zipball/master).

Предпочтительно вы можете загрузить sqlmap, клонируя [Git](https://github.com/sqlmapproject/sqlmap) репозиторий:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap работает из коробки с [Python](http://www.python.org/download/) версии **2.6.x** и **2.7.x** на любой платформе.

Использование
----

Чтобы получить список основных опций и вариантов выбора, используйте:

    python sqlmap.py -h

Чтобы получить список всех опций и вариантов выбора, используйте:

    python sqlmap.py -hh

Вы можете найти пробный запуск [тут](https://asciinema.org/a/46601).
Чтобы получить обзор возможностей sqlmap, список поддерживаемых функций и описание всех параметров и переключателей, а также примеры, вам рекомендуется ознакомится с [пользовательским мануалом](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

Ссылки
----

* Основной сайт: http://sqlmap.org
* Скачивание: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) или [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* Канал новостей RSS: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Отслеживание проблем: https://github.com/sqlmapproject/sqlmap/issues
* Пользовательский мануал: https://github.com/sqlmapproject/sqlmap/wiki
* Часто задаваемые вопросы (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* Twitter: [@sqlmap](https://twitter.com/sqlmap)
* Демки: [http://www.youtube.com/user/inquisb/videos](http://www.youtube.com/user/inquisb/videos)
* Скриншоты: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots

Переводы
----

* [Russian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ru-RUS.md)
* [Bulgarian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-bg-BG.md)
* [Chinese](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-zh-CN.md)
* [Croatian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-hr-HR.md)
* [French](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-fr-FR.md)
* [Greek](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-gr-GR.md)
* [Indonesian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-id-ID.md)
* [Italian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-it-IT.md)
* [Japanese](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ja-JP.md)
* [Polish](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-pl-PL.md)
* [Portuguese](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-pt-BR.md)
* [Spanish](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-es-MX.md)
* [Turkish](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-tr-TR.md)
