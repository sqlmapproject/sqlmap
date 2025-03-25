# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

**sqlmap** est un outil Open Source de test d'intrusion. Cet outil permet d'automatiser le processus de détection et d'exploitation des failles d'injection SQL afin de prendre le contrôle des serveurs de base de données. __sqlmap__ dispose d'un puissant moteur de détection utilisant les techniques les plus récentes et les plus dévastatrices de tests d'intrusion comme L'Injection SQL, qui permet d'accéder à la base de données, au système de fichiers sous-jacent et permet aussi l'exécution des commandes sur le système d'exploitation.

----

![Les Captures d'écran](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Les captures d'écran disponible [ici](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) démontrent des fonctionnalités de __sqlmap__.

Installation
----

Vous pouvez télécharger le fichier "tarball" le plus récent en cliquant [ici](https://github.com/sqlmapproject/sqlmap/tarball/master). Vous pouvez aussi télécharger l'archive zip la plus récente [ici](https://github.com/sqlmapproject/sqlmap/zipball/master).

De préférence, télécharger __sqlmap__ en le [clonant](https://github.com/sqlmapproject/sqlmap):

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap fonctionne sur n'importe quel système d'exploitation avec la version **2.6**, **2.7** et **3.x** de [Python](https://www.python.org/download/)

Utilisation
----

Pour afficher une liste des fonctions de bases et des commutateurs (switches), tapez:

    python sqlmap.py -h

Pour afficher une liste complète des options et des commutateurs (switches), tapez:

    python sqlmap.py -hh

Vous pouvez regarder une vidéo [ici](https://asciinema.org/a/46601) pour plus d'exemples.
Pour obtenir un aperçu des ressources de __sqlmap__, une liste des fonctionnalités prises en charge, la description de toutes les options, ainsi que des exemples, nous vous recommandons de consulter [le wiki](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

Liens
----

* Page d'acceuil: https://sqlmap.org
* Téléchargement: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) ou [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* Commits RSS feed: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Suivi des issues: https://github.com/sqlmapproject/sqlmap/issues
* Manuel de l'utilisateur: https://github.com/sqlmapproject/sqlmap/wiki
* Foire aux questions (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://twitter.com/sqlmap)
* Démonstrations: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* Les captures d'écran: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
