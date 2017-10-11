# sqlmap

[![Build Status](https://api.travis-ci.org/sqlmapproject/sqlmap.svg?branch=master)](https://api.travis-ci.org/sqlmapproject/sqlmap) [![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap to open sourceowe narzędzie do testów penetracyjnych, które automatyzuje procesy detekcji, przejmowania i testowania odporności serwerów SQL na podatność na iniekcję niechcianego kodu. Zawiera potężny mechanizm detekcji, wiele niszowych funkcji dla zaawansowanych testów penetracyjnych oraz szeroki wachlarz opcji począwszy od identyfikacji bazy danych, poprzez wydobywanie z nich danych, a nawet pozwalającuch na dostęp do systemu plików o uruchamianie poleceń w systemie operacyjnym serwera poprzez niestandardowe połączenia.

Zrzuty ekranowe
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Możesz odwiedzić [kolekcję zrzutów](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) demonstruującą na wiki niektóre możliwości.

Instalacja
----

Najnowsze tarball archiwum jest dostępne po klikcięciu [tutaj](https://github.com/sqlmapproject/sqlmap/tarball/master) lub najnowsze zipball archiwum po kliknięciu [tutaj](https://github.com/sqlmapproject/sqlmap/zipball/master).

Można również pobrać sqlmap klonując rezozytorium [Git](https://github.com/sqlmapproject/sqlmap):

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

do użycia sqlmap potrzebny jest [Python](http://www.python.org/download/) w wersji **2.6.x** lub **2.7.x** na dowolnej platformie systemowej.

Sposób użycia
----

Aby uzyskać listę podstawowych funkcji i parametrów użyj polecenia:

    python sqlmap.py -h

Aby uzyskać listę wszystkich funkcji i parametrów użyj polecenia:

    python sqlmap.py -hh

Przykładowy wynik działania dostępny [tutaj](https://asciinema.org/a/46601).
Aby uzyskać listę wszystkich dostępnych fukcji, parametrów i opisów ich działania wraz z przykładami użycia sqlnap proponujemy odwiedzić [instrukjcę użytkowania](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

Odnośniki
----

* Strona projektu: http://sqlmap.org
* Pobieranie: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) or [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* RSS feed: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Raportowanie błędów: https://github.com/sqlmapproject/sqlmap/issues
* Instrukcja użytkowania: https://github.com/sqlmapproject/sqlmap/wiki
* Często zadawane pytania (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* Twitter: [@sqlmap](https://twitter.com/sqlmap)
* Dema: [http://www.youtube.com/user/inquisb/videos](http://www.youtube.com/user/inquisb/videos)
* Zrzuty ekranowe: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
