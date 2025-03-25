# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap là một công cụ kiểm tra thâm nhập mã nguồn mở, nhằm tự động hóa quá trình phát hiện, khai thác lỗ hổng SQL injection và tiếp quản các máy chủ cơ sở dữ liệu. Công cụ này đi kèm với 
một hệ thống phát hiện mạnh mẽ, nhiều tính năng thích hợp cho người kiểm tra thâm nhập (pentester) và một loạt các tùy chọn bao gồm phát hiện, truy xuất dữ liệu từ cơ sở dữ liệu, truy cập file hệ thống và thực hiện các lệnh trên hệ điều hành từ xa.

Ảnh chụp màn hình
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Bạn có thể truy cập vào [bộ sưu tập ảnh chụp màn hình](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) - nơi trình bày một số tính năng có thể tìm thấy trong wiki.

Cài đặt
----


Bạn có thể tải xuống tập tin nén tar mới nhất bằng cách nhấp vào [đây](https://github.com/sqlmapproject/sqlmap/tarball/master) hoặc tập tin nén zip mới nhất bằng cách nhấp vào [đây](https://github.com/sqlmapproject/sqlmap/zipball/master).

Tốt hơn là bạn nên tải xuống sqlmap bằng cách clone về repo [Git](https://github.com/sqlmapproject/sqlmap):

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap hoạt động hiệu quả với [Python](https://www.python.org/download/) phiên bản **2.6**, **2.7** và **3.x** trên bất kì hệ điều hành nào.

Sử dụng
----

Để có được danh sách các tùy chọn cơ bản và switch, hãy chạy:

    python sqlmap.py -h

Để có được danh sách tất cả các tùy chọn và switch, hãy chạy:

    python sqlmap.py -hh

Bạn có thể xem video demo [tại đây](https://asciinema.org/a/46601).
Để có cái nhìn tổng quan về sqlmap, danh sách các tính năng được hỗ trợ và mô tả về tất cả các tùy chọn, cùng với các ví dụ, bạn nên tham khảo [hướng dẫn sử dụng](https://github.com/sqlmapproject/sqlmap/wiki/Usage) (Tiếng Anh).

Liên kết
----

* Trang chủ: https://sqlmap.org
* Tải xuống: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) hoặc [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* Nguồn cấp dữ liệu RSS về commits: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Theo dõi issue: https://github.com/sqlmapproject/sqlmap/issues
* Hướng dẫn sử dụng: https://github.com/sqlmapproject/sqlmap/wiki
* Các câu hỏi thường gặp (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://twitter.com/sqlmap)
* Demo: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* Ảnh chụp màn hình: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
