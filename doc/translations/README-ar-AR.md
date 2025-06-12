# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![X](https://img.shields.io/badge/x-@sqlmap-blue.svg)](https://x.com/sqlmap)

<div dir=rtl>

برنامج  sqlmap هو أداة اختبار اختراق مفتوحة المصدر تقوم بأتمتة عملية اكتشاف واستغلال ثغرات حقن SQL والسيطرة على خوادم قواعد البيانات. يأتي مع محرك كشف قوي، والعديد من الميزات المتخصصة لمختبر الاختراق المحترف، ومجموعة واسعة من الخيارات بما في ذلك تحديد بصمة قاعدة البيانات، واستخراج البيانات من قاعدة البيانات، والوصول إلى نظام الملفات الأساسي، وتنفيذ الأوامر على نظام التشغيل عبر اتصالات خارج النطاق.

لقطات الشاشة
----

<div dir=ltr>

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

<div dir=rtl>

يمكنك زيارة [مجموعة لقطات الشاشة](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) التي توضح بعض الميزات في الويكي.

التثبيت
----

يمكنك تحميل أحدث إصدار tarball بالنقر [هنا](https://github.com/sqlmapproject/sqlmap/tarball/master) أو أحدث إصدار zipball بالنقر [هنا](https://github.com/sqlmapproject/sqlmap/zipball/master).

يفضل تحميل sqlmap عن طريق استنساخ مستودع [Git](https://github.com/sqlmapproject/sqlmap):

<div dir=ltr>

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

<div dir=rtl>

يعمل sqlmap مباشرة مع [Python](https://www.python.org/download/) إصدار **2.6** و **2.7** و **3.x** على أي نظام تشغيل.

الاستخدام
----

للحصول على قائمة بالخيارات والمفاتيح الأساسية استخدم:

<div dir=ltr>

    python sqlmap.py -h

<div dir=rtl>

للحصول على قائمة بجميع الخيارات والمفاتيح استخدم:

<div dir=ltr>

    python sqlmap.py -hh

<div dir=rtl>

يمكنك العثور على مثال للتشغيل [هنا](https://asciinema.org/a/46601).
للحصول على نظرة عامة على إمكانيات sqlmap، وقائمة الميزات المدعومة، ووصف لجميع الخيارات والمفاتيح، مع الأمثلة، ننصحك بمراجعة [دليل المستخدم](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

الروابط
----

* الصفحة الرئيسية: https://sqlmap.org
* التحميل: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) أو [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* تغذية التحديثات RSS: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* تتبع المشكلات: https://github.com/sqlmapproject/sqlmap/issues
* دليل المستخدم: https://github.com/sqlmapproject/sqlmap/wiki
* الأسئلة الشائعة: https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* تويتر: [@sqlmap](https://x.com/sqlmap)
* العروض التوضيحية: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* لقطات الشاشة: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots 