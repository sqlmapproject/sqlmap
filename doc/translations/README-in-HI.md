# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![x](https://img.shields.io/badge/x-@sqlmap-blue.svg)](https://x.com/sqlmap)

sqlmap एक ओपन सोर्स प्रवेश परीक्षण उपकरण है जो SQL इन्जेक्शन दोषों की पहचान और उपयोग की प्रक्रिया को स्वचलित करता है और डेटाबेस सर्वरों को अधिकृत कर लेता है। इसके साथ एक शक्तिशाली पहचान इंजन, अंतिम प्रवेश परीक्षक के लिए कई निचले विशेषताएँ और डेटाबेस प्रिंट करने, डेटाबेस से डेटा निकालने, नीचे के फ़ाइल सिस्टम तक पहुँचने और आउट-ऑफ-बैंड कनेक्शन के माध्यम से ऑपरेटिंग सिस्टम पर कमांड चलाने के लिए कई बड़े रेंज के स्विच शामिल हैं।

चित्रसंवाद
----

![स्क्रीनशॉट](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

आप [विकि पर](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) कुछ फीचर्स की दिखाते हुए छवियों का संग्रह देख सकते हैं।

स्थापना
----

आप नवीनतम तारबाल को [यहां क्लिक करके](https://github.com/sqlmapproject/sqlmap/tarball/master) या नवीनतम ज़िपबॉल को [यहां क्लिक करके](https://github.com/sqlmapproject/sqlmap/zipball/master) डाउनलोड कर सकते हैं।

प्राथमिकत: आप sqlmap को [गिट](https://github.com/sqlmapproject/sqlmap) रिपॉजिटरी क्लोन करके भी डाउनलोड कर सकते हैं:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap [Python](https://www.python.org/download/) संस्करण **2.6**, **2.7** और **3.x** पर किसी भी प्लेटफार्म पर तुरंत काम करता है।

उपयोग
----

मौलिक विकल्पों और स्विच की सूची प्राप्त करने के लिए:

    python sqlmap.py -h

सभी विकल्पों और स्विच की सूची प्राप्त करने के लिए:

    python sqlmap.py -hh

आप [यहां](https://asciinema.org/a/46601) एक नमूना चलाने का पता लगा सकते हैं। sqlmap की क्षमताओं की एक अवलोकन प्राप्त करने, समर्थित फीचर्स की सूची और सभी विकल्पों और स्विच का वर्णन, साथ ही उदाहरणों के साथ, आपको [उपयोगकर्ता मैन्युअल](https://github.com/sqlmapproject/sqlmap/wiki/Usage) पर परामर्श दिया जाता है।

लिंक
----

* मुखपृष्ठ: https://sqlmap.org
* डाउनलोड: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) या [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* संवाद आरएसएस फ़ीड: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* समस्या ट्रैकर: https://github.com/sqlmapproject/sqlmap/issues
* उपयोगकर्ता मैन्युअल: https://github.com/sqlmapproject/sqlmap/wiki
* अक्सर पूछे जाने वाले प्रश्न (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* ट्विटर: [@sqlmap](https://x.com/sqlmap)
* डेमो: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* स्क्रीनशॉट: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
* 
