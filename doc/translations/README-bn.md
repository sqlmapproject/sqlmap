# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap একটি ওপেন সোর্স পেনেট্রেশন টেস্টিং টুল যা SQL ইনজেকশন ত্রুটিগুলি সনাক্ত এবং এক্সপ্লয়েট করার প্রক্রিয়া এবং ডেটাবেজ সার্ভারগুলি দখল করার প্রক্রিয়া স্বয়ংক্রিয় করে। এটি একটি শক্তিশালী সনাক্তকরণ ইঞ্জিন, চূড়ান্ত অনুপ্রবেশকারীর জন্য অনেকগুলি নির্দিষ্ট বৈশিষ্ট্য এবং বিস্তৃত পরিসরের সুইচগুলির সাথে আসে, যার মধ্যে ডেটাবেজ ফিঙ্গারপ্রিন্টিং, ডাটাবেস থেকে তথ্য আহরণ, অন্তর্নিহিত ফাইল সিস্টেম অ্যাক্সেস করা এবং আউট-অফ-ব্যান্ড সংযোগগুলির মাধ্যমে অপারেটিং সিস্টেমে কমান্ড এক্সিকিউট করা অন্তর্ভুক্ত রয়েছে।

স্ক্রিনশট
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

আপনি উইকিতে কিছু বৈশিষ্ট্য প্রদর্শনকারী [স্ক্রিনশট সংগ্রহ](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) দেখতে পারেন।

ইনস্টলেশন
----

আপনি [এখানে](https://github.com/sqlmapproject/sqlmap/tarball/master) ক্লিক করে সর্বশেষতম tarball ডাউনলোড করতে পারেন অথবা [এখানে](https://github.com/sqlmapproject/sqlmap/zipball/master) ক্লিক করে সর্বশেষতম zipball ডাউনলোড করতে পারেন।

আরও, আপনি [Git](https://github.com/sqlmapproject/sqlmap) রিপোজিটরি ক্লোন করে sqlmap ডাউনলোড করতে পারেন:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap যেকোনো প্ল্যাটফর্মে [Python](https://www.python.org/download/) ভার্সন **2.6**, **2.7** and **3.x** এর সাথে সরাসরি কাজ করে।

ব্যবহার
----

মৌলিক অপশন এবং সুইচগুলির তালিকা পেতে ব্যবহার করুন:

    python sqlmap.py -h

সকল অপশন এবং সুইচগুলির তালিকা পেতে ব্যবহার করুন:

    python sqlmap.py -hh

আপনি [এখানে](https://asciinema.org/a/46601) একটি স্যাম্পল রান খুজে পাবেন।
sqlmap এর ক্ষমতা, সাপোর্টেড ফিচারগুলোর তালিকা এবং উদাহরণ সহ সমস্ত অপশন এবং সুইচগুলির বিবরণ সম্পর্কে একটি ওভারভিউ পেতে, [ব্যবহারকারী নির্দেশিকা](https://github.com/sqlmapproject/sqlmap/wiki/Usage) দেখুন/দেখতে পরামর্শ দেওয়া হলো।

Links
----

* হোমপেজ: https://sqlmap.org
* ডাউনলোড: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) or [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* কমিটস RSS ফিড: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* ইস্যু ট্র্যাকার: https://github.com/sqlmapproject/sqlmap/issues
* ব্যবহারকারী নির্দেশিকা: https://github.com/sqlmapproject/sqlmap/wiki
* সাধারণ জিজ্ঞাসা (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://twitter.com/sqlmap)
* ডেমো: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* স্ক্রিনশট: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
