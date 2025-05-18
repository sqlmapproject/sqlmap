# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![x](https://img.shields.io/badge/x-@sqlmap-blue.svg)](https://x.com/sqlmap)

sqlmap - это инструмент для тестирования уязвимостей с открытым исходным кодом, который автоматизирует процесс обнаружения и использования ошибок SQL-инъекций и захвата серверов баз данных. Он оснащен мощным механизмом обнаружения, множеством приятных функций для профессионального тестера уязвимостей и широким спектром скриптов, которые упрощают работу с базами данных, от сбора данных из базы данных, до доступа к базовой файловой системе и выполнения команд в операционной системе через out-of-band соединение.

Скриншоты
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Вы можете посетить [набор скриншотов](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) демонстрируемые некоторые функции в wiki.

Установка
----

Вы можете скачать последнюю версию tarball, нажав [сюда](https://github.com/sqlmapproject/sqlmap/tarball/master) или последний zipball, нажав  [сюда](https://github.com/sqlmapproject/sqlmap/zipball/master).

Предпочтительно вы можете загрузить sqlmap, клонируя [Git](https://github.com/sqlmapproject/sqlmap) репозиторий:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap работает из коробки с [Python](https://www.python.org/download/) версии **2.6**, **2.7** и **3.x** на любой платформе.

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

* Основной сайт: https://sqlmap.org
* Скачивание: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) или [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* Канал новостей RSS: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Отслеживание проблем: https://github.com/sqlmapproject/sqlmap/issues
* Пользовательский мануал: https://github.com/sqlmapproject/sqlmap/wiki
* Часто задаваемые вопросы (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://x.com/sqlmap)
* Демки: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* Скриншоты: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
