#!/bin/bash

VERSION=1.0.8
TMP_DIR=/tmp/pypi
mkdir $TMP_DIR
cd $TMP_DIR
cat > $TMP_DIR/setup.py << EOF
#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from setuptools import setup, find_packages

setup(
    name='sqlmap',
    version='$VERSION',
    description="Automatic SQL injection and database takeover tool",
    author='Bernardo Damele Assumpcao Guimaraes, Miroslav Stampar',
    author_email='bernardo@sqlmap.org, miroslav@sqlmap.org',
    url='https://sqlmap.org',
    download_url='https://github.com/sqlmapproject/sqlmap/archive/$VERSION.zip',
    license='GPLv2',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
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
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
EOF
for file in $(find sqlmap -type f | grep -v -E "\.(git|yml)"); do echo include $file >> MANIFEST.in; done
python setup.py sdist
python setup.py sdist upload
rm -rf $TMP_DIR