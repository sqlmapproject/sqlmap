# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap je alat namijenjen za penetracijsko testiranje koji automatizira proces detekcije i eksploatacije sigurnosnih propusta SQL injekcije te preuzimanje poslužitelja baze podataka. Dolazi s moćnim mehanizmom za detekciju, mnoštvom korisnih opcija za napredno penetracijsko testiranje te široki spektar opcija od onih za prepoznavanja baze podataka, preko dohvaćanja podataka iz baze, do pristupa zahvaćenom datotečnom sustavu i izvršavanja komandi na operacijskom sustavu korištenjem tzv. "out-of-band" veza.

Slike zaslona
----

![Slika zaslona](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Možete posjetiti [kolekciju slika zaslona](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) gdje se demonstriraju neke od značajki na wiki stranicama.

Instalacija
----

Možete preuzeti zadnji tarball klikom [ovdje](https://github.com/sqlmapproject/sqlmap/tarball/master) ili zadnji zipball klikom [ovdje](https://github.com/sqlmapproject/sqlmap/zipball/master).

Po mogućnosti, možete preuzeti sqlmap kloniranjem [Git](https://github.com/sqlmapproject/sqlmap) repozitorija:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap radi bez posebnih zahtjeva korištenjem [Python](https://www.python.org/download/) verzije **2.6**, **2.7** i/ili **3.x** na bilo kojoj platformi.

Korištenje
----

Kako biste dobili listu osnovnih opcija i prekidača koristite:

    python sqlmap.py -h

Kako biste dobili listu svih opcija i prekidača koristite:

    python sqlmap.py -hh

Možete pronaći primjer izvršavanja [ovdje](https://asciinema.org/a/46601).
Kako biste dobili pregled mogućnosti sqlmap-a, liste podržanih značajki te opis svih opcija i prekidača, zajedno s primjerima, preporučen je uvid u [korisnički priručnik](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

Poveznice
----

* Početna stranica: https://sqlmap.org
* Preuzimanje: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) ili [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* RSS feed promjena u kodu: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Prijava problema: https://github.com/sqlmapproject/sqlmap/issues
* Korisnički priručnik: https://github.com/sqlmapproject/sqlmap/wiki
* Najčešće postavljena pitanja (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://twitter.com/sqlmap)
* Demo: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* Slike zaslona: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
