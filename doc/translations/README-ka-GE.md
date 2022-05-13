# sqlmap ![](https://i.imgur.com/fe85aVR.png)

[![.github/workflows/tests.yml](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml/badge.svg)](https://github.com/sqlmapproject/sqlmap/actions/workflows/tests.yml) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

sqlmap არის შეღწევადობის ტესტირებისათვის განკუთვილი ინსტრუმენტი, რომლის კოდიც ღიად არის ხელმისაწვდომი. ინსტრუმენტი ახდენს SQL-ინექციის სისუსტეების აღმოჩენისა, გამოყენების და მონაცემთა ბაზათა სერვერების დაუფლების პროცესების ავტომატიზაციას. იგი აღჭურვილია მძლავრი აღმომჩენი მექანიძმით, შეღწევადობის პროფესიონალი ტესტერისათვის შესაფერისი ბევრი ფუნქციით და სკრიპტების ფართო სპექტრით, რომლებიც შეიძლება გამოყენებულ იქნეს მრავალი მიზნით, მათ შორის: მონაცემთა ბაზიდან მონაცემების შეგროვებისათვის, ძირითად საფაილო სისტემაზე წვდომისათვის და out-of-band კავშირების გზით ოპერაციულ სისტემაში ბრძანებათა შესრულებისათვის.

ეკრანის ანაბეჭდები
----

![ეკრანის ანაბეჭდი](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

შეგიძლიათ ესტუმროთ [ეკრანის ანაბეჭდთა კოლექციას](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots), სადაც დემონსტრირებულია ინსტრუმენტის ზოგიერთი ფუნქცია.

ინსტალაცია
----

თქვენ შეგიძლიათ უახლესი tar-არქივის ჩამოტვირთვა [აქ](https://github.com/sqlmapproject/sqlmap/tarball/master) დაწკაპუნებით, ან უახლესი zip-არქივის ჩამოტვირთვა [აქ](https://github.com/sqlmapproject/sqlmap/zipball/master) დაწკაპუნებით.

ასევე შეგიძლიათ (და სასურველია) sqlmap-ის ჩამოტვირთვა [Git](https://github.com/sqlmapproject/sqlmap)-საცავის (repository) კლონირებით:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap ნებისმიერ პლატფორმაზე მუშაობს [Python](https://www.python.org/download/)-ის **2.6**, **2.7** და **3.x** ვერსიებთან.

გამოყენება
----

ძირითადი ვარიანტებისა და პარამეტრების ჩამონათვალის მისაღებად გამოიყენეთ ბრძანება:

    python sqlmap.py -h

ვარიანტებისა და პარამეტრების სრული ჩამონათვალის მისაღებად გამოიყენეთ ბრძანება:

    python sqlmap.py -hh

გამოყენების მარტივი მაგალითი შეგიძლიათ იხილოთ [აქ](https://asciinema.org/a/46601). sqlmap-ის შესაძლებლობათა მიმოხილვის, მხარდაჭერილი ფუნქციონალისა და ყველა ვარიანტის აღწერების მისაღებად გამოყენების მაგალითებთან ერთად, გირჩევთ, იხილოთ [მომხმარებლის სახელმძღვანელო](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

ბმულები
----

* საწყისი გვერდი: https://sqlmap.org
* ჩამოტვირთვა: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) ან [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* RSS არხი: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* პრობლემებისათვის თვალყურის დევნება: https://github.com/sqlmapproject/sqlmap/issues
* მომხმარებლის სახელმძღვანელო: https://github.com/sqlmapproject/sqlmap/wiki
* ხშირად დასმული კითხვები (ხდკ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* Twitter: [@sqlmap](https://twitter.com/sqlmap)
* დემონსტრაციები: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)
* ეკრანის ანაბეჭდები: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
