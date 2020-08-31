#!/bin/bash

# NOTE: this script is for dev usage after AV something something

DIR=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

cd $DIR/../..
for file in $(find -regex ".*\.[a-z]*_" -type f | grep -v wordlist); do python extra/cloak/cloak.py -d -i $file; done

cd $DIR/../cloak
sed -i 's/KEY = .*/KEY = b"'`python -c 'import random; import string; print("".join(random.sample(string.ascii_letters + string.digits, 16)))'`'"/g' cloak.py

cd $DIR/../..
for file in $(find -regex ".*\.[a-z]*_" -type f | grep -v wordlist); do python extra/cloak/cloak.py -i `echo $file | sed 's/_$//g'`; done

git clean -f > /dev/null
