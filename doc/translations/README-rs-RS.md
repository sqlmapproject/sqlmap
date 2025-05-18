# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![x](https://img.shields.io/badge/x-@sqlmap-blue.svg)](https://x.com/sqlmap)

sqlmap je alat otvorenog koda namenjen za penetraciono testiranje koji automatizuje proces detekcije i eksploatacije sigurnosnih propusta SQL injekcije i preuzimanje baza podataka. Dolazi s moćnim mehanizmom za detekciju, mnoštvom korisnih opcija za napredno penetracijsko testiranje te široki spektar opcija od onih za prepoznavanja baze podataka, preko uzimanja podataka iz baze, do pristupa zahvaćenom fajl sistemu i izvršavanja komandi na operativnom sistemu korištenjem tzv. "out-of-band" veza.

Slike
----

![Slika](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Možete posetiti [kolekciju slika](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) gde su demonstrirane neke od e se demonstriraju neke od funkcija na wiki stranicama.

Instalacija
----

Možete preuzeti najnoviji tarball klikom [ovde](https://github.com/sqlmapproject/sqlmap/tarball/master) ili najnoviji zipball klikom [ovde](https://github.com/sqlmapproject/sqlmap/zipball/master).

Opciono, možete preuzeti sqlmap kloniranjem [Git](https://github.com/sqlmapproject/sqlmap) repozitorija:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap radi bez posebnih zahteva korištenjem [Python](https://www.python.org/download/) verzije **2.6**, **2.7** i/ili **3.x** na bilo kojoj platformi.

Korišćenje
----

Kako biste dobili listu osnovnih opcija i prekidača koristite:

    python sqlmap.py -h

Kako biste dobili listu svih opcija i prekidača koristite:

    python sqlmap.py -hh

Možete pronaći primer izvršavanja [ovde](https://asciinema.org/a/46601).
Kako biste dobili pregled mogućnosti sqlmap-a, liste podržanih funkcija, te opis svih opcija i prekidača, zajedno s primerima, preporučen je uvid u [korisnički priručnik](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

Linkovi
----

* Početna stranica: https://sqlmap.org
* Preuzimanje: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) ili [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* RSS feed promena u kodu: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Prijava problema: https://github.com/sqlmapproject/sqlmap/issues
* Korisnički priručnik: https://github.com/sqlmapproject/sqlmap/wiki
* Najčešće postavljena pitanja (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://x.com/sqlmap)
* Demo: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* Slike: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
