#!/bin/bash

if [ ! -f ~/.pypirc ]; then
    echo "File ~/.pypirc is missing"
    exit 1
fi

declare -x SCRIPTPATH="${0}"
SETTINGS="${SCRIPTPATH%/*}/../../lib/core/settings.py"
VERSION=$(cat $SETTINGS | grep -E "^VERSION =" | cut -d '"' -f 2 | cut -d '.' -f 1-3)
TYPE=pip
TMP_DIR=/tmp/pypi
mkdir $TMP_DIR
cd $TMP_DIR
cat > $TMP_DIR/setup.py << EOF
#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from setuptools import setup, find_packages

setup(
    name='sqlmap',
    version='$VERSION',
    description='Automatic SQL injection and database takeover tool',
    long_description=open('README.rst').read(),
    long_description_content_type='text/x-rst',
    author='Bernardo Damele Assumpcao Guimaraes, Miroslav Stampar',
    author_email='bernardo@sqlmap.org, miroslav@sqlmap.org',
    url='https://sqlmap.org',
    project_urls={
        'Documentation': 'https://github.com/sqlmapproject/sqlmap/wiki',
        'Source': 'https://github.com/sqlmapproject/sqlmap/',
        'Tracker': 'https://github.com/sqlmapproject/sqlmap/issues',
    },
    download_url='https://github.com/sqlmapproject/sqlmap/archive/$VERSION.zip',
    license='GNU General Public License v2 (GPLv2)',
    packages=['sqlmap'],
    package_dir={'sqlmap':'sqlmap'},
    include_package_data=True,
    zip_safe=False,
    # https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Environment :: Console',
        'Topic :: Database',
        'Topic :: Security',
    ],
    entry_points={
        'console_scripts': [
            'sqlmap = sqlmap.sqlmap:main',
        ],
    },
)
EOF
wget "https://github.com/sqlmapproject/sqlmap/archive/$VERSION.zip" -O sqlmap.zip
unzip sqlmap.zip
rm sqlmap.zip
mv "sqlmap-$VERSION" sqlmap
cat > sqlmap/__init__.py << EOF
#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
EOF
cat > README.rst << "EOF"
sqlmap
======

|Python 2.6|2.7|3.x| |License| |Twitter|

sqlmap is an open source penetration testing tool that automates the
process of detecting and exploiting SQL injection flaws and taking over
of database servers. It comes with a powerful detection engine, many
niche features for the ultimate penetration tester and a broad range of
switches lasting from database fingerprinting, over data fetching from
the database, to accessing the underlying file system and executing
commands on the operating system via out-of-band connections.

Screenshots
-----------

.. figure:: https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png
   :alt: Screenshot


You can visit the `collection of
screenshots <https://github.com/sqlmapproject/sqlmap/wiki/Screenshots>`__
demonstrating some of features on the wiki.

Installation
------------

You can use pip to install and/or upgrade the sqlmap to latest (monthly) tagged version with: ::

    pip install --upgrade sqlmap

Alternatively, you can download the latest tarball by clicking
`here <https://github.com/sqlmapproject/sqlmap/tarball/master>`__ or
latest zipball by clicking
`here <https://github.com/sqlmapproject/sqlmap/zipball/master>`__.

If you prefer fetching daily updates, you can download sqlmap by cloning the
`Git <https://github.com/sqlmapproject/sqlmap>`__ repository:

::

    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

sqlmap works out of the box with
`Python <http://www.python.org/download/>`__ version **2.6**, **2.7** and
**3.x** on any platform.

Usage
-----

To get a list of basic options and switches use:

::

    sqlmap -h

To get a list of all options and switches use:

::

    sqlmap -hh

You can find a sample run `here <https://asciinema.org/a/46601>`__. To
get an overview of sqlmap capabilities, list of supported features and
description of all options and switches, along with examples, you are
advised to consult the `user's
manual <https://github.com/sqlmapproject/sqlmap/wiki/Usage>`__.

Links
-----

-  Homepage: https://sqlmap.org
-  Download:
   `.tar.gz <https://github.com/sqlmapproject/sqlmap/tarball/master>`__
   or `.zip <https://github.com/sqlmapproject/sqlmap/zipball/master>`__
-  Commits RSS feed:
   https://github.com/sqlmapproject/sqlmap/commits/master.atom
-  Issue tracker: https://github.com/sqlmapproject/sqlmap/issues
-  User's manual: https://github.com/sqlmapproject/sqlmap/wiki
-  Frequently Asked Questions (FAQ):
   https://github.com/sqlmapproject/sqlmap/wiki/FAQ
-  X: https://twitter.com/sqlmap
-  Demos: http://www.youtube.com/user/inquisb/videos
-  Screenshots: https://github.com/sqlmapproject/sqlmap/wiki/Screenshots

.. |Python 2.6|2.7|3.x| image:: https://img.shields.io/badge/python-2.6|2.7|3.x-yellow.svg
   :target: https://www.python.org/
.. |License| image:: https://img.shields.io/badge/license-GPLv2-red.svg
   :target: https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE
.. |Twitter| image:: https://img.shields.io/badge/twitter-@sqlmap-blue.svg
   :target: https://twitter.com/sqlmap

.. pandoc --from=markdown --to=rst --output=README.rst sqlmap/README.md
.. http://rst.ninjs.org/
EOF
sed -i "s/^VERSION =.*/VERSION = \"$VERSION\"/g" sqlmap/lib/core/settings.py
sed -i "s/^TYPE =.*/TYPE = \"$TYPE\"/g" sqlmap/lib/core/settings.py
for file in $(find sqlmap -type f | grep -v -E "\.(git|yml)"); do echo include $file >> MANIFEST.in; done
python setup.py sdist bdist_wheel
twine check dist/*
twine upload --config-file=~/.pypirc dist/*
rm -rf $TMP_DIR
