# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap은 SQL 인젝션 결함 탐지 및 활용, 데이터베이스 서버 장악 프로세스를 자동화 하는 오픈소스 침투 테스팅 도구입니다. 최고의 침투 테스터, 데이터베이스 핑거프린팅 부터 데이터베이스 데이터 읽기, 대역 외 연결을 통한 기반 파일 시스템 접근 및 명령어 실행에 걸치는 광범위한 스위치들을 위한 강력한 탐지 엔진과 다수의 편리한 기능이 탑재되어 있습니다.

스크린샷
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

또는, wiki에 나와있는 몇몇 기능을 보여주는 [스크린샷 모음](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) 을 방문하실 수 있습니다.

설치
----

[여기](https://github.com/sqlmapproject/sqlmap/tarball/master)를 클릭하여 최신 버전의 tarball 파일, 또는 [여기](https://github.com/sqlmapproject/sqlmap/zipball/master)를 클릭하여 최신 zipball 파일을 다운받으실 수 있습니다.

가장 선호되는 방법으로, [Git](https://github.com/sqlmapproject/sqlmap) 저장소를 복제하여 sqlmap을 다운로드 할 수 있습니다:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap은 [Python](https://www.python.org/download/) 버전 **2.6**, **2.7** 그리고 **3.x** 을 통해 모든 플랫폼 위에서 사용 가능합니다.

사용법
----

기본 옵션과 스위치 목록을 보려면 다음 명령어를 사용하세요:

    python sqlmap.py -h

전체 옵션과 스위치 목록을 보려면 다음 명령어를 사용하세요:

    python sqlmap.py -hh

[여기](https://asciinema.org/a/46601)를 통해 사용 샘플들을 확인할 수 있습니다.
sqlmap의 능력, 지원되는 기능과 모든 옵션과 스위치들의 목록을 예제와 함께 보려면, [사용자 매뉴얼](https://github.com/sqlmapproject/sqlmap/wiki/Usage)을 참고하시길 권장드립니다.

링크
----

* 홈페이지: https://sqlmap.org
* 다운로드: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) or [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* RSS 피드 커밋: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Issue tracker: https://github.com/sqlmapproject/sqlmap/issues
* 사용자 매뉴얼: https://github.com/sqlmapproject/sqlmap/wiki
* 자주 묻는 질문 (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* 트위터: [@sqlmap](https://twitter.com/sqlmap)
* 시연 영상: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* 스크린샷: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
