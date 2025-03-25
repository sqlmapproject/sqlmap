# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap adalah perangkat lunak sumber terbuka yang digunakan untuk melakukan uji penetrasi, mengotomasi proses deteksi, eksploitasi kelemahan _SQL injection_ serta pengambil-alihan server basis data.

sqlmap dilengkapi dengan pendeteksi canggih dan fitur-fitur handal yang berguna bagi _penetration tester_. Perangkat lunak ini menawarkan berbagai cara untuk mendeteksi basis data bahkan dapat mengakses sistem file dan mengeksekusi perintah dalam sistem operasi melalui koneksi _out-of-band_.

Tangkapan Layar
----

![Tangkapan Layar](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Anda juga dapat mengunjungi [koleksi tangkapan layar](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) yang mendemonstrasikan beberapa fitur dalam wiki.

Instalasi
----

Anda dapat mengunduh tarball versi terbaru [di sini](https://github.com/sqlmapproject/sqlmap/tarball/master) atau zipball [di sini](https://github.com/sqlmapproject/sqlmap/zipball/master).

Sebagai alternatif, Anda dapat mengunduh sqlmap dengan melakukan _clone_ pada repositori [Git](https://github.com/sqlmapproject/sqlmap):

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap berfungsi langsung pada [Python](https://www.python.org/download/) versi **2.6**, **2.7** dan **3.x** pada platform apapun.

Penggunaan
----

Untuk mendapatkan daftar opsi dasar gunakan perintah:

    python sqlmap.py -h

Untuk mendapatkan daftar opsi lanjutan gunakan perintah:

    python sqlmap.py -hh

Anda dapat mendapatkan contoh penggunaan [di sini](https://asciinema.org/a/46601).

Untuk mendapatkan gambaran singkat kemampuan sqlmap, daftar fitur yang didukung, deskripsi dari semua opsi, berikut dengan contohnya. Anda disarankan untuk membaca [Panduan Pengguna](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

Tautan
----

* Situs: https://sqlmap.org
* Unduh: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) atau [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* RSS Feed Dari Commits: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Pelacak Masalah: https://github.com/sqlmapproject/sqlmap/issues
* Wiki Manual Penggunaan: https://github.com/sqlmapproject/sqlmap/wiki
* Pertanyaan Yang Sering Ditanyakan (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://twitter.com/sqlmap)
* Video Demo [#1](https://www.youtube.com/user/inquisb/videos) dan [#2](https://www.youtube.com/user/stamparm/videos)
* Tangkapan Layar: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
