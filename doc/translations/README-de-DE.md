# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![x](https://img.shields.io/badge/x-@sqlmap-blue.svg)](https://x.com/sqlmap)

sqlmap ist ein quelloffenes Penetrationstest Werkzeug, das die Entdeckung, Ausnutzung und Übernahme von SQL injection Schwachstellen automatisiert. Es kommt mit einer mächtigen Erkennungs-Engine, vielen Nischenfunktionen für den ultimativen Penetrationstester und einem breiten Spektrum an Funktionen von Datenbankerkennung, abrufen von Daten aus der Datenbank, zugreifen auf das unterliegende Dateisystem bis hin zur Befehlsausführung auf dem Betriebssystem mit Hilfe von out-of-band Verbindungen.

Screenshots
---

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Du kannst eine [Sammlung von Screenshots](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots), die einige der Funktionen demonstrieren, auf dem Wiki einsehen.

Installation
---

[Hier](https://github.com/sqlmapproject/sqlmap/tarball/master) kannst du das neueste TAR-Archiv herunterladen und [hier](https://github.com/sqlmapproject/sqlmap/zipball/master) das neueste ZIP-Archiv.

Vorzugsweise kannst du sqlmap herunterladen, indem du das [GIT](https://github.com/sqlmapproject/sqlmap) Repository klonst:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
    
sqlmap funktioniert sofort mit den [Python](https://www.python.org/download/) Versionen 2.6, 2.7 und 3.x auf jeder Plattform.

Benutzung
---

Um eine Liste aller grundsätzlichen Optionen und Switches zu bekommen, nutze diesen Befehl:

    python sqlmap.py -h
    
Um eine Liste alles Optionen und Switches zu bekommen, nutze diesen Befehl:

    python sqlmap.py -hh
    
Ein Probelauf ist [hier](https://asciinema.org/a/46601) zu finden. Um einen Überblick über sqlmap's Fähigkeiten, unterstütze Funktionen und eine Erklärung aller Optionen und Switches, zusammen mit Beispielen, zu erhalten, wird das [Benutzerhandbuch](https://github.com/sqlmapproject/sqlmap/wiki/Usage) empfohlen.

Links
---

* Webseite: https://sqlmap.org
* Download: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) or [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* Commits RSS feed: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Problemverfolgung: https://github.com/sqlmapproject/sqlmap/issues
* Benutzerhandbuch: https://github.com/sqlmapproject/sqlmap/wiki
* Häufig gestellte Fragen (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://x.com/sqlmap)
* Demonstrationen: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* Screenshots: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
