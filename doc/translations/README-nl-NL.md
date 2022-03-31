# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap is een open source penetratie test tool dat het proces automatiseert van het detecteren en exploiteren van SQL injectie fouten en het overnemen van database servers. Het wordt geleverd met een krachtige detectie-engine, vele niche-functies voor de ultieme penetratietester, en een breed scala aan switches, waaronder database fingerprinting, het overhalen van gegevens uit de database, toegang tot het onderliggende bestandssysteem, en het uitvoeren van commando's op het besturingssysteem via out-of-band verbindingen.

Screenshots
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Je kunt de [collectie met screenshots](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) bezoeken voor een demonstratie van sommige functies in the wiki.

Installatie
----

Je kunt de laatste tarball installeren door [hier](https://github.com/sqlmapproject/sqlmap/tarball/master) te klikken of de laatste zipball door [hier](https://github.com/sqlmapproject/sqlmap/zipball/master) te klikken.

Bij voorkeur, kun je sqlmap downloaden door de [Git](https://github.com/sqlmapproject/sqlmap) repository te clonen:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap werkt op alle platformen met de volgende [Python](https://www.python.org/download/) versies: **2.6**, **2.7** en **3.x**.

Gebruik
----

Om een lijst van basisopties en switches te krijgen gebruik:

    python sqlmap.py -h

Om een lijst van alle opties en switches te krijgen gebruik:

    python sqlmap.py -hh

Je kunt [hier](https://asciinema.org/a/46601) een proefrun vinden.
Voor een overzicht van de mogelijkheden van sqlmap, een lijst van ondersteunde functies, en een beschrijving van alle opties en switches, samen met voorbeelden, wordt u aangeraden de [gebruikershandleiding](https://github.com/sqlmapproject/sqlmap/wiki/Usage) te raadplegen.

Links
----

* Homepage: https://sqlmap.org
* Download: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) of [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* RSS feed: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Probleem tracker: https://github.com/sqlmapproject/sqlmap/issues
* Gebruikers handleiding: https://github.com/sqlmapproject/sqlmap/wiki
* Vaak gestelde vragen (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* Twitter: [@sqlmap](https://twitter.com/sqlmap)
* Demos: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* Screenshots: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
