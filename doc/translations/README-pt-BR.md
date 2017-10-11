# sqlmap

[![Build Status](https://api.travis-ci.org/sqlmapproject/sqlmap.svg?branch=master)](https://api.travis-ci.org/sqlmapproject/sqlmap) [![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap é uma ferramenta de teste de penetração de código aberto que automatiza o processo de detecção e exploração de falhas de injeção SQL. Com essa ferramenta é possível assumir total controle de servidores de banco de dados em páginas web vulneráveis, inclusive de base de dados fora do sistema invadido. Ele possui um motor de detecção poderoso, empregando as últimas e mais devastadoras técnicas de teste de penetração por SQL Injection, que permite acessar a base de dados, o sistema de arquivos subjacente e executar comandos no sistema operacional.

Imagens
----

![Imagem](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Você pode visitar a [coleção de imagens](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) que demonstra alguns dos recursos apresentados na wiki.

Instalação
----

Você pode baixar o arquivo tar mais recente clicando [aqui]
(https://github.com/sqlmapproject/sqlmap/tarball/master) ou o arquivo zip mais recente clicando [aqui](https://github.com/sqlmapproject/sqlmap/zipball/master).

De preferência, você pode baixar o sqlmap clonando o repositório [Git](https://github.com/sqlmapproject/sqlmap):

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap funciona em [Python](http://www.python.org/download/) nas versões **2.6.x** e **2.7.x** em todas as plataformas.

Como usar
----

Para obter uma lista das opções básicas faça:

    python sqlmap.py -h

Para obter a lista completa de opções faça:

    python sqlmap.py -hh

Você pode encontrar alguns exemplos [aqui](https://asciinema.org/a/46601).
Para ter uma visão geral dos recursos do sqlmap, lista de recursos suportados e a descrição de todas as opções, juntamente com exemplos, aconselhamos que você consulte o [manual do usuário](https://github.com/sqlmapproject/sqlmap/wiki).

Links
----

* Homepage: http://sqlmap.org
* Download: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) ou [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* Commits RSS feed: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Issue tracker: https://github.com/sqlmapproject/sqlmap/issues
* Manual do Usuário: https://github.com/sqlmapproject/sqlmap/wiki
* Perguntas frequentes (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* Twitter: [@sqlmap](https://twitter.com/sqlmap)
* Demonstrações: [#1](http://www.youtube.com/user/inquisb/videos) e [#2](http://www.youtube.com/user/stamparm/videos)
* Imagens: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
