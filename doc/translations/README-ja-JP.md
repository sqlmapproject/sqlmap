# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmapはオープンソースのペネトレーションテスティングツールです。SQLインジェクションの脆弱性の検出、活用、そしてデータベースサーバ奪取のプロセスを自動化します。
強力な検出エンジン、ペネトレーションテスターのための多くのニッチ機能、持続的なデータベースのフィンガープリンティングから、データベースのデータ取得やアウトオブバンド接続を介したオペレーティング・システム上でのコマンド実行、ファイルシステムへのアクセスなどの広範囲に及ぶスイッチを提供します。

スクリーンショット
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

wikiに載っているいくつかの機能のデモをスクリーンショットで見ることができます。 [スクリーンショット集](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots)

インストール
----

最新のtarballを [こちら](https://github.com/sqlmapproject/sqlmap/tarball/master) から、最新のzipballを [こちら](https://github.com/sqlmapproject/sqlmap/zipball/master) からダウンロードできます。

[Git](https://github.com/sqlmapproject/sqlmap) レポジトリをクローンして、sqlmapをダウンロードすることも可能です。:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmapは、 [Python](https://www.python.org/download/) バージョン **2.6**, **2.7** または **3.x** がインストールされていれば、全てのプラットフォームですぐに使用できます。

使用方法
----

基本的なオプションとスイッチの使用方法をリストで取得するには:

    python sqlmap.py -h

全てのオプションとスイッチの使用方法をリストで取得するには:

    python sqlmap.py -hh

実行例を [こちら](https://asciinema.org/a/46601) で見ることができます。
sqlmapの概要、機能の一覧、全てのオプションやスイッチの使用方法を例とともに、 [ユーザーマニュアル](https://github.com/sqlmapproject/sqlmap/wiki/Usage) で確認することができます。

リンク
----

* ホームページ: https://sqlmap.org
* ダウンロード: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) or [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* コミットのRSSフィード: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* 課題管理: https://github.com/sqlmapproject/sqlmap/issues
* ユーザーマニュアル: https://github.com/sqlmapproject/sqlmap/wiki
* よくある質問 (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://twitter.com/sqlmap)
* デモ: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* スクリーンショット: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
