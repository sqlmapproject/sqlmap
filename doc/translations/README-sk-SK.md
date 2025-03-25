# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap je open source nástroj na penetračné testovanie, ktorý automatizuje proces detekovania a využívania chýb SQL injekcie a preberania databázových serverov. Je vybavený výkonným detekčným mechanizmom, mnohými výklenkovými funkciami pre dokonalého penetračného testera a širokou škálou prepínačov vrátane odtlačkov databázy, cez načítanie údajov z databázy, prístup k základnému súborovému systému a vykonávanie príkazov v operačnom systéme prostredníctvom mimopásmových pripojení.

Snímky obrazovky
----

![snímka obrazovky](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Môžete navštíviť [zbierku snímok obrazovky](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots), ktorá demonštruuje niektoré funkcie na wiki.

Inštalácia
----

Najnovší tarball si môžete stiahnuť kliknutím [sem](https://github.com/sqlmapproject/sqlmap/tarball/master) alebo najnovší zipball kliknutím [sem](https://github.com/sqlmapproject/sqlmap/zipball/master).

Najlepšie je stiahnuť sqlmap naklonovaním [Git](https://github.com/sqlmapproject/sqlmap) repozitára:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap funguje bez problémov s programovacím jazykom [Python](https://www.python.org/download/) vo verziách **2.6**, **2.7** a **3.x** na akejkoľvek platforme.

Využitie
----

Na získanie zoznamu základných možností a prepínačov, použite:

    python sqlmap.py -h

Na získanie zoznamu všetkých možností a prepínačov, použite:

    python sqlmap.py -hh

Vzorku behu nájdete [tu](https://asciinema.org/a/46601).
Ak chcete získať prehľad o možnostiach sqlmap, zoznam podporovaných funkcií a opis všetkých možností a prepínačov spolu s príkladmi, odporúčame vám nahliadnuť do [Používateľskej príručky](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

Linky
----

* Domovská stránka: https://sqlmap.org
* Stiahnutia: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) alebo [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* Zdroje RSS Commits: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Sledovač problémov: https://github.com/sqlmapproject/sqlmap/issues
* Používateľská príručka: https://github.com/sqlmapproject/sqlmap/wiki
* Často kladené otázky (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://twitter.com/sqlmap)
* Demá: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* Snímky obrazovky: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots