# sqlmap

[![Build Status](https://api.travis-ci.org/sqlmapproject/sqlmap.svg?branch=master)](https://api.travis-ci.org/sqlmapproject/sqlmap) [![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/doc/COPYING) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap e' un tool open source di penetration testing tool che automatizza il processo di riconoscimento ed exploiting di problemi di SQL injection e extrafiltration di database servers. E' dotato di un potente motore di riconoscimento, molte interessanti funzioni per il penetration tester e una vasta scelta di opzioni dal database fingerprinting, all'estrazione dei dati dal database, all'accesso al filesystem sottostante ed esecuzione di comandi sul sistema operativo on the operating system con connessioni out-of-band.

Screenshots
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

E' possibile visitare la url [collection of screenshots](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) per la dimostrazione di alcune interessanti funzioni sul wiki.

Installazione
----

E' possibile scaricare l'ultima tarball cliccando [qui](https://github.com/sqlmapproject/sqlmap/tarball/master) o l'ultima zipball cliccando  [qui](https://github.com/sqlmapproject/sqlmap/zipball/master).

E' preferibile scaricare sqlmap clonando il [Git](https://github.com/sqlmapproject/sqlmap) repository:

    git clone https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap funziona con [Python](http://www.python.org/download/) versione **2.6.x** e **2.7.x** su qualsiasi piattaforma.

Utilizzo
----

Per avere una lista base delle opzioni e dei parametri utilizzare:

    python sqlmap.py -h

Per avere una lista di tutte le opzioni e dei parametri utilizzare:

    python sqlmap.py -hh

E' possibile trovare una dimostrazione [qui](https://gist.github.com/stamparm/5335217).
Per avere una idea delle funzionalita di sqlmap, la lista delle funzioni supportate e la descrizione di tutte le opzioni e parametri, comprensivo di esempi, e' consigliato consultare il  [manuale utente](https://github.com/sqlmapproject/sqlmap/wiki).

Links
----

* Homepage: http://sqlmap.org
* Download: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) or [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* Commits RSS feed: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Issue tracker: https://github.com/sqlmapproject/sqlmap/issues
* User's manual: https://github.com/sqlmapproject/sqlmap/wiki
* Frequently Asked Questions (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* Mailing list subscription: https://lists.sourceforge.net/lists/listinfo/sqlmap-users
* Mailing list RSS feed: http://rss.gmane.org/messages/complete/gmane.comp.security.sqlmap
* Mailing list archive: http://news.gmane.org/gmane.comp.security.sqlmap
* Twitter: [@sqlmap](https://twitter.com/sqlmap)
* Demos: [http://www.youtube.com/user/inquisb/videos](http://www.youtube.com/user/inquisb/videos)
* Screenshots: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots

Traduzioni
----

* [Chinese](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-zh-CN.md)
* [Croatian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-hr-HR.md)
* [Greek](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-gr-GR.md)
* [Indonesian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-id-ID.md)
* [Italiano](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-it-IT.md)
* [Portuguese](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-pt-BR.md)
* [Spanish](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-es-MX.md)
* [Turkish](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-tr-TR.md)
