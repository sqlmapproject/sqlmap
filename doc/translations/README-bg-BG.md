# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![x](https://img.shields.io/badge/x-@sqlmap-blue.svg)](https://x.com/sqlmap)

sqlmap e инструмент за тестване и проникване, с отворен код, който автоматизира процеса на откриване и използване на недостатъците на SQL база данните чрез SQL инжекция, която ги взима от сървъра. Снабден е с мощен детектор, множество специални функции за най-добрия тестер и широк спектър от функции, които могат да се използват за множество цели - извличане на данни от базата данни, достъп до основната файлова система и изпълняване на команди на операционната система.

Демо снимки
----

![Снимка на екрана](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Можете да посетите [колекцията от снимки на екрана](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots), показващи някои  функции, качени на wiki.

Инсталиране
----

Може да изтеглине най-новите tar архиви като кликнете [тук](https://github.com/sqlmapproject/sqlmap/tarball/master) или най-новите zip архиви като кликнете [тук](https://github.com/sqlmapproject/sqlmap/zipball/master).

За предпочитане е да изтеглите sqlmap като клонирате [Git](https://github.com/sqlmapproject/sqlmap) хранилището:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap работи самостоятелно с [Python](https://www.python.org/download/) версия **2.6**, **2.7** и **3.x** на всички платформи.

Използване
----

За да получите списък с основните опции използвайте:

    python sqlmap.py -h

За да получите списък с всички опции използвайте:

    python sqlmap.py -hh

Може да намерите пример за използване на sqlmap [тук](https://asciinema.org/a/46601).
За да разберете възможностите на sqlmap, списък на поддържаните функции и описание на всички опции, заедно с примери, се препоръчва да се разгледа [упътването](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

Връзки
----

* Начална страница: https://sqlmap.org
* Изтегляне: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) or [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* RSS емисия: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Проследяване на проблеми и въпроси: https://github.com/sqlmapproject/sqlmap/issues
* Упътване: https://github.com/sqlmapproject/sqlmap/wiki
* Често задавани въпроси (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://x.com/sqlmap)
* Демо: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* Снимки на екрана: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
