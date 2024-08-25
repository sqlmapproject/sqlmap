# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)


<div dir=rtl>



بەرنامەی `sqlmap` بەرنامەیەکی تاقیکردنەوەی چوونە ژوورەوەی سەرچاوە کراوەیە کە بە شێوەیەکی ئۆتۆماتیکی بنکەدراوە کە کێشەی ئاسایشی SQL Injection یان هەیە دەدۆزێتەوە. ئەم بەرنامەیە بزوێنەرێکی بەهێزی دیاریکردنی تێدایە. هەروەها کۆمەڵێک سکریپتی بەرفراوانی هەیە کە ئاسانکاری دەکات بۆ پیشەییەکانی تاقیکردنەوەی دزەکردن(penetration tester) بۆ کارکردن لەگەڵ بنکەدراوە. لە کۆکردنەوەی زانیاری دەربارەی بانکی داتا تا دەستگەیشتن بە داتاکانی سیستەم و جێبەجێکردنی فەرمانەکان لە ڕێگەی پەیوەندی Out Of Band لە سیستەمی کارگێڕدا.


سکرین شاتی ئامرازەکە 
----


<div dir=ltr>



![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)


<div dir=rtl>

بۆ بینینی [کۆمەڵێک سکرین شات و سکریپت](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) دەتوانیت سەردانی ویکیەکە بکەیت.


دامەزراندن
----

بۆ دابەزاندنی نوێترین وەشانی tarball، کلیک [لێرە](https://github.com/sqlmapproject/sqlmap/tarball/master) یان دابەزاندنی نوێترین وەشانی zipball بە کلیککردن لەسەر [لێرە](https://github.com/sqlmapproject/sqlmap/zipball/master) دەتوانیت ئەم کارە بکەیت.

باشترە بتوانیت sqlmap دابەزێنیت بە کلۆنکردنی کۆگای [Git](https://github.com/sqlmapproject/sqlmap):

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap لە دەرەوەی سندوق کاردەکات لەگەڵ [Python](https://www.python.org/download/) وەشانی **2.6**، **2.7** و **3.x** لەسەر هەر پلاتفۆرمێک.

چۆنیەتی بەکارهێنان
----

بۆ بەدەستهێنانی لیستی بژاردە سەرەتاییەکان و سویچەکان ئەمانە بەکاربهێنە:

    python sqlmap.py -h

بۆ بەدەستهێنانی لیستی هەموو بژاردە و سویچەکان ئەمە بەکار بێنا:

    python sqlmap.py -hh

دەتوانن نمونەی ڕانکردنێک بدۆزنەوە [لێرە](https://asciinema.org/a/46601).
بۆ بەدەستهێنانی تێڕوانینێکی گشتی لە تواناکانی sqlmap، لیستی تایبەتمەندییە پشتگیریکراوەکان، و وەسفکردنی هەموو هەڵبژاردن و سویچەکان، لەگەڵ نموونەکان، ئامۆژگاریت دەکرێت کە ڕاوێژ بە [دەستنووسی بەکارهێنەر](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

بەستەرەکان
----

* ماڵپەڕی سەرەکی: https://sqlmap.org
* داگرتن: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) یان [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* فیدی RSS جێبەجێ دەکات: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* شوێنپێهەڵگری کێشەکان: https://github.com/sqlmapproject/sqlmap/issues
* ڕێنمایی بەکارهێنەر: https://github.com/sqlmapproject/sqlmap/wiki
* پرسیارە زۆرەکان (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://twitter.com/sqlmap)
* دیمۆ: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* وێنەی شاشە: https://github.com/sqlmapproject/sqlmap/wiki/وێنەی شاشە

وەرگێڕانەکان
