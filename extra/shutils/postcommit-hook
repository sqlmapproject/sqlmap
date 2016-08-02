#!/bin/bash

SETTINGS="../../lib/core/settings.py"

declare -x SCRIPTPATH="${0}"

FULLPATH=${SCRIPTPATH%/*}/$SETTINGS

if [ -f $FULLPATH ]
then
    LINE=$(grep -o ${FULLPATH} -e 'VERSION = "[0-9.]*"')
    declare -a LINE
    NEW_TAG=$(python -c "import re, sys, time; version = re.search('\"([0-9.]*)\"', sys.argv[1]).group(1); _ = version.split('.'); print '.'.join(_[:-1]) if len(_) == 4 and _[-1] == '0' else ''" "$LINE")
    if [ -n "$NEW_TAG" ]
    then
        git commit -am "Automatic monthly tagging"
        echo "Creating new tag ${NEW_TAG}"
        git tag $NEW_TAG
        git push origin $NEW_TAG
        echo "Going to push PyPI package"
        /bin/bash ${SCRIPTPATH%/*}/pypi.sh
    fi
fi
