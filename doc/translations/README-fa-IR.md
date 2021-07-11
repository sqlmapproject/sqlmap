# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![Build Status](https://api.travis-ci.org/sqlmapproject/sqlmap.svg?branch=master)](https://travis-ci.org/sqlmapproject/sqlmap) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![PyPI version](https://badge.fury.io/py/sqlmap.svg)](https://badge.fury.io/py/sqlmap) [![GitHub closed issues](https://img.shields.io/github/issues-closed-raw/sqlmapproject/sqlmap.svg?colorB=ff69b4)](https://github.com/sqlmapproject/sqlmap/issues?q=is%3Aissue+is%3Aclosed) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

<!-- Start RTL Direction -->
<div dir="rtl">

`sqlmap` یک ابزار تست نفوذ متن‌باز است، که فرایند تست نفوذپذیری `SQL injection` و گرفتن کنترل دیتابیس های SQL را به شکل خودکار انجام می‌دهد. این برنامه به همراه یک موتور تشخیص قدرتمند، امکانات پیشرفته برای تست نفوذ گوناگون، و همچنین طیف گسترده‌ای از سوئیچ ها شامل دیتابیس fingerprinting، استخراج داده از دیتابیس، دستیابی به سیستم فایل های زیرین، و اجرای دستورات در سیستم عامل به وسیله اتصالات خارجی (out-of-band) عرضه می‌شود.

اسکرین‌شات
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

برای مشاهده اسکرین‌شات‌های بیشتر می‌توانید به [بخش آموزش -> اسکرین‌شات‌ها](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) مراجعه کنید.

نحوه نصب
----

برای دانلود آخرین نسخه tarball، [اینجا](https://github.com/sqlmapproject/sqlmap/tarball/master) یا برای دانلود آخرین نسخه zipball [اینجا](https://github.com/sqlmapproject/sqlmap/zipball/master) کلیک کنید.

ترجیحا، شما می‌توانید `sqlmap` را با clone کردن از مخزن [Git](https://github.com/sqlmapproject/sqlmap) نیز دانلود کنید.

<div dir="ltr">

```
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

</div>

`sqlmap` به صورت خارج از جعبه برروی هر پلتفرمی با پایتون نسخه‌های **2.6**, **2.7** و **3.x** کار می‌کند.

نحوه استفاده
----

دریافت لیست ساده آرگومان‌ و سوئیچ ها:

<div dir="ltr">

```
python sqlmap.py -h
```

</div>

دریافت لیست کامل آرگومان و سوئیچ ها:

<div dir="ltr">

```
python sqlmap.py -hh
```

</div>

شما می‌توانید یک نمونه اجرا شده را در [اینجا](https://asciinema.org/a/46601) یپدا کنید.

همچنین، برای دریافت یک نمای کلی از قابلیت و امکانات sqlmap، و توضیحات کامل آرگومان و سوئیچ‌ها در کنار مثال‌ها به شما توصیه می‌شود که [کتابچه راهنمای کاربران](https://github.com/sqlmapproject/sqlmap/wiki/Usage) را مطالعه کنید.

لینک‌ها
----

* صفحه‌اصلی: http://sqlmap.org
* دانلود: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) یا [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* خبرخوان کامیت‌ها: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* پیگری مشکلات: https://github.com/sqlmapproject/sqlmap/issues
* راهنمای کاربران: https://github.com/sqlmapproject/sqlmap/wiki
* سوالات متداول: https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* تویتر: [@sqlmap](https://twitter.com/sqlmap)
* کانال‌یوتیوب: [http://www.youtube.com/user/inquisb/videos](http://www.youtube.com/user/inquisb/videos)
* اسکرین‌شات‌ها: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots

<!-- End RTL Direction -->
</div>
