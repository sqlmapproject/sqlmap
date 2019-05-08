# sqlmap

[![Build Status](https://api.travis-ci.org/sqlmapproject/sqlmap.svg?branch=master)](https://travis-ci.org/sqlmapproject/sqlmap) [![Python 2.6|2.7|3.x](https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![PyPI version](https://badge.fury.io/py/sqlmap.svg)](https://badge.fury.io/py/sqlmap) [![GitHub closed issues](https://img.shields.io/github/issues-closed-raw/sqlmapproject/sqlmap.svg?colorB=ff69b4)](https://github.com/sqlmapproject/sqlmap/issues?q=is%3Aissue+is%3Aclosed) [![Twitter](https://img.shields.io/badge/twitter-@sqlmap-blue.svg)](https://twitter.com/sqlmap)

Το sqlmap είναι πρόγραμμα ανοιχτού κώδικα, που αυτοματοποιεί την εύρεση και εκμετάλλευση ευπαθειών τύπου SQL Injection σε βάσεις δεδομένων. Έρχεται με μια δυνατή μηχανή αναγνώρισης ευπαθειών, πολλά εξειδικευμένα χαρακτηριστικά για τον απόλυτο penetration tester όπως και με ένα μεγάλο εύρος επιλογών αρχίζοντας από την αναγνώριση της βάσης δεδομένων, κατέβασμα δεδομένων της βάσης, μέχρι και πρόσβαση στο βαθύτερο σύστημα αρχείων και εκτέλεση εντολών στο απευθείας στο λειτουργικό μέσω εκτός ζώνης συνδέσεων.

Εικόνες
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

Μπορείτε να επισκεφτείτε τη [συλλογή από εικόνες](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots) που επιδεικνύουν κάποια από τα χαρακτηριστικά.

Εγκατάσταση
----

Έχετε τη δυνατότητα να κατεβάσετε την τελευταία tarball πατώντας [εδώ](https://github.com/sqlmapproject/sqlmap/tarball/master) ή την τελευταία zipball πατώντας [εδώ](https://github.com/sqlmapproject/sqlmap/zipball/master).

Κατά προτίμηση, μπορείτε να κατεβάσετε το sqlmap κάνοντας κλώνο το [Git](https://github.com/sqlmapproject/sqlmap) αποθετήριο:

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

Το sqlmap λειτουργεί χωρίς περαιτέρω κόπο με την [Python](http://www.python.org/download/) έκδοσης **2.6**, **2.7** και **3.x** σε όποια πλατφόρμα.

Χρήση
----

Για να δείτε μια βασική λίστα από επιλογές πατήστε:

    python sqlmap.py -h

Για να πάρετε μια λίστα από όλες τις επιλογές πατήστε:

    python sqlmap.py -hh

Μπορείτε να δείτε ένα δείγμα λειτουργίας του προγράμματος [εδώ](https://asciinema.org/a/46601).
Για μια γενικότερη άποψη των δυνατοτήτων του sqlmap, μια λίστα των υποστηριζόμενων χαρακτηριστικών και περιγραφή για όλες τις επιλογές, μαζί με παραδείγματα, καλείστε να συμβουλευτείτε το [εγχειρίδιο χρήστη](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

Σύνδεσμοι
----

* Αρχική σελίδα: http://sqlmap.org
* Λήψεις: [.tar.gz](https://github.com/sqlmapproject/sqlmap/tarball/master) ή [.zip](https://github.com/sqlmapproject/sqlmap/zipball/master)
* Commits RSS feed: https://github.com/sqlmapproject/sqlmap/commits/master.atom
* Προβλήματα: https://github.com/sqlmapproject/sqlmap/issues
* Εγχειρίδιο Χρήστη: https://github.com/sqlmapproject/sqlmap/wiki
* Συχνές Ερωτήσεις (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* Twitter: [@sqlmap](https://twitter.com/sqlmap)
* Demos: [http://www.youtube.com/user/inquisb/videos](http://www.youtube.com/user/inquisb/videos)
* Εικόνες: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
