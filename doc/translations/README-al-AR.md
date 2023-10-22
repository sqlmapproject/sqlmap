# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap هو أداة اختبار الاختراق مفتوحة المصدر تقوم بتوتير عملية اكتشاف واستغلال عيوب حقن SQL واستيلاء على خوادم قواعد البيانات. إنه يأتي مع محرك اكتشاف قوي والعديد من الميزات المخصصة لاختبار الاختراق النهائي ومجموعة واسعة من الخيارات بما في ذلك بصمة قاعدة البيانات واستخراج البيانات من قاعدة البيانات والوصول إلى نظام الملفات الأساسي وتنفيذ الأوامر على نظام التشغيل من خلال اتصالات خارج النطاق.

لقطات شاشة
----

![لقطة شاشة](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

يمكنك زيارة [مجموعة من اللقطات](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) التي تظهر بعض الميزات على الويكي.

التثبيت
----

يمكنك تنزيل أحدث حزمة تاربال بالنقر [هنا](https://github.com/sqlmapproject/sqlmap/tarball/master) أو آخر حزمة زيببال بالنقر [هنا](https://github.com/sqlmapproject/sqlmap/zipball/master).

بشكل مفضل، يمكنك تنزيل sqlmap عن طريق استنساخ مستودع [Git](https://github.com/sqlmapproject/sqlmap):

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

يعمل sqlmap بشكل مباشر مع إصدار **2.6**, **2.7** و **3.x** من [Python](https://www.python.org/download/) على أي منصة.

الاستخدام
----

للحصول على قائمة بالخيارات والمفاتيح الأساسية، استخدم:

    python sqlmap.py -h

للحصول على قائمة بجميع الخيارات والمفاتيح، استخدم:

    python sqlmap.py -hh

يمكنك العثور على عرض عينة [هنا](https://asciinema.org/a/46601).
للحصول على نظرة عامة على قدرات sqlmap، وقائمة بالميزات المدعومة، ووصف لجميع الخيارات والمفاتيح، بالإضافة إلى أمثلة، يُفضل عليك الاطلاع على [دليل المستخدم](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

روابط
----

* الصفحة الرئيسية: https://sqlmap.org
* التنزيل: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) أو [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* تغذية آر إس إس لسجل التعديلات: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* متتبع المشاكل: https://github.com/sqlmapproject/sqlmap/issues
* دليل المستخدم: https://github.com/sqlmapproject/sqlmap/wiki
* الأسئلة الشائعة (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* تويتر: [@sqlmap](https://twitter.com/sqlmap)
* عروض توضيحية: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* لقطات شاشة: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
