# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![X](https://img.shields.io/badge/x-@sqlmap-blue.svg)](https://x.com/sqlmap)

**SQLMap** একটি ওপেন সোর্স পেনিট্রেশন টেস্টিং টুল যা স্বয়ংক্রিয়ভাবে SQL ইনজেকশন দুর্বলতা সনাক্ত ও শোষণ করতে এবং ডাটাবেস সার্ভার নিয়ন্ত্রণে নিতে সহায়তা করে। এটি একটি শক্তিশালী ডিটেকশন ইঞ্জিন, উন্নত ফিচার এবং পেনিট্রেশন টেস্টারদের জন্য দরকারি বিভিন্ন অপশন নিয়ে আসে। এর মাধ্যমে ডাটাবেস ফিঙ্গারপ্রিন্টিং, ডাটাবেস থেকে তথ্য আহরণ, ফাইল সিস্টেম অ্যাক্সেস, এবং অপারেটিং সিস্টেমে কমান্ড চালানোর মতো কাজ করা যায়, এমনকি আউট-অফ-ব্যান্ড সংযোগ ব্যবহার করেও।



স্ক্রিনশট
---

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

আপনি [Wiki-তে](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) গিয়ে SQLMap-এর বিভিন্ন ফিচারের ডেমোনস্ট্রেশন দেখতে পারেন।

ইনস্টলেশন
---
সর্বশেষ টারবলে ডাউনলোড করুন [এখানে](https://github.com/sqlmapproject/sqlmap/tarball/master) অথবা সর্বশেষ জিপ ফাইল [এখানে](https://github.com/sqlmapproject/sqlmap/zipball/master)।

অথবা, সরাসরি [Git](https://github.com/sqlmapproject/sqlmap) রিপোজিটরি থেকে ক্লোন করুন:

```
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

SQLMap স্বয়ংক্রিয়ভাবে [Python](https://www.python.org/download/) **2.6**, **2.7** এবং **3.x** সংস্করণে যেকোনো প্ল্যাটফর্মে কাজ করে।



ব্যবহারের নির্দেশিকা
---

বেসিক অপশন এবং সুইচসমূহ দেখতে ব্যবহার করুন:

```
python sqlmap.py -h
```

সমস্ত অপশন ও সুইচের তালিকা পেতে ব্যবহার করুন:

```
python sqlmap.py -hh
```

আপনি একটি নমুনা রান দেখতে পারেন [এখানে](https://asciinema.org/a/46601)।
SQLMap-এর সম্পূর্ণ ফিচার, ক্ষমতা, এবং কনফিগারেশন সম্পর্কে বিস্তারিত জানতে [ব্যবহারকারীর ম্যানুয়াল](https://github.com/sqlmapproject/sqlmap/wiki/Usage) পড়ার পরামর্শ দেওয়া হচ্ছে।



লিঙ্কসমূহ
---

* হোমপেজ: https://sqlmap.org
* ডাউনলোড: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) অথবা [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* কমিটস RSS ফিড: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* ইস্যু ট্র্যাকার: https://github.com/sqlmapproject/sqlmap/issues
* ব্যবহারকারীর ম্যানুয়াল: https://github.com/sqlmapproject/sqlmap/wiki
* সচরাচর জিজ্ঞাসিত প্রশ্ন (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://x.com/sqlmap)
* ডেমো ভিডিও: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* স্ক্রিনশট: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots

