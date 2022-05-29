# Giới thiệu sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

Công cụ kiểm thử `sqlmap` là một công cụ kiểm tra thâm nhập với mã nguồn mở, nhằm tự động hóa tiến trình tìm kiếm, khai thác lỗ hổng của ngôn ngữ SQL -sau đó, chiếm đoạt các máy chủ CSDL (cơ sở dữ liệu / database). Được phát triển với khả năng tìm kiếm lỗ hổng mạnh mẽ, nhiều tính năng thích hợp cho người kiểm tra thâm nhập (pentester) hỗ trợ người dùng với nhiều tính năng tích hợp như nhận dạng CSDL, truy xuất dữ liệu từ CSDL, truy cập tệp hệ thống và khởi chạy các lệnh trên hệ điều hành từ xa.

Tổng quan
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Bạn có thể truy cập vào [bộ sưu tập ảnh chụp màn hình](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots), chúng trình bày một số tính năng có thể tìm thấy trong wiki.

Cài đặt
----


Bạn có thể tải xuống tập tin nén tar mới nhất bằng cách nhấp vào [đây](https://github.com/sqlmapproject/sqlmap/tarball/master) hoặc tập tin nén zip mới nhất bằng cách nhấp vào [đây](https://github.com/sqlmapproject/sqlmap/zipball/master).

Tốt hơn là bạn nên tải xuống sqlmap bằng cách clone với [Git](https://github.com/sqlmapproject/sqlmap):

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap hoạt động hiệu quả với [Python](https://www.python.org/download/) phiên bản **2.6**, **2.7** và **3.x** trên bất kì hệ điều hành nào.

Sử dụng
----

Để có được danh sách các tùy chọn cơ bản, hãy sử dụng:

    python sqlmap.py -h

Để có được danh sách tất cả các tùy chọn, hãy sử dụng:

    python sqlmap.py -hh

Bạn có thể xem video chạy thử [tại đây](https://asciinema.org/a/46601).
Để có cái nhìn tổng quan về các khả năng của sqlmap, danh sách các tính năng được hỗ trợ và mô tả về tất cả các tùy chọn, cùng với các ví dụ, bạn nên tham khảo [hướng dẫn sử dụng](https://github.com/sqlmapproject/sqlmap/wiki/Usage) (Tiếng Anh).

Liên kết
----

* Trang chủ: https://sqlmap.org
* Tải xuống: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) hoặc [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* Nguồn cấp dữ liệu RSS về commits: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Theo dõi vấn đề: https://github.com/sqlmapproject/sqlmap/issues
* Hướng dẫn sử dụng: https://github.com/sqlmapproject/sqlmap/wiki
* Các câu hỏi thường gặp (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* Twitter: [@sqlmap](https://twitter.com/sqlmap)
* Demo: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* Ảnh chụp màn hình: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
