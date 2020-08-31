#!/bin/bash

# NOTE: this script is for dev usage after AV something something

DIR=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

cd $DIR/../../data/shell
find -regex ".*backdoor\.[a-z]*_" -type f -exec python ../../extra/cloak/cloak.py -d -i '{}' \;
find -regex ".*stager\.[a-z]*_" -type f -exec python ../../extra/cloak/cloak.py -d -i '{}' \;

cd $DIR/../cloak
sed -i 's/KEY = .*/KEY = b"'`python -c 'import random; import string; print("".join(random.sample(string.ascii_letters + string.digits, 16)))'`'"/g' cloak.py

cd $DIR/../../data/shell
find -regex ".*backdoor\.[a-z]*" -type f -exec python ../../extra/cloak/cloak.py -i '{}' \;
find -regex ".*stager\.[a-z]*" -type f -exec python ../../extra/cloak/cloak.py -i '{}' \;

git clean -f > /dev/null
