#!/bin/bash

: '
cat > .git/hooks/pre-commit << EOF
#!/bin/bash

source ./extra/shutils/precommit-hook.sh
EOF

chmod +x .git/hooks/pre-commit
'

PROJECT="../../"
SETTINGS="../../lib/core/settings.py"
DIGEST="../../data/txt/sha256sums.txt"

declare -x SCRIPTPATH="${0}"

PROJECT_FULLPATH=${SCRIPTPATH%/*}/$PROJECT
SETTINGS_FULLPATH=${SCRIPTPATH%/*}/$SETTINGS
DIGEST_FULLPATH=${SCRIPTPATH%/*}/$DIGEST

git diff $SETTINGS_FULLPATH | grep "VERSION =" > /dev/null && exit 0

if [ -f $SETTINGS_FULLPATH ]
then
    LINE=$(grep -o ${SETTINGS_FULLPATH} -e 'VERSION = "[0-9.]*"')
    declare -a LINE
    INCREMENTED=$(python -c "import re, sys, time; version = re.search('\"([0-9.]*)\"', sys.argv[1]).group(1); _ = version.split('.'); _.extend([0] * (4 - len(_))); _[-1] = str(int(_[-1]) + 1); month = str(time.gmtime().tm_mon); _[-1] = '0' if _[-2] != month else _[-1]; _[-2] = month; print sys.argv[1].replace(version, '.'.join(_))" "$LINE")
    if [ -n "$INCREMENTED" ]
    then
        sed -i "s/${LINE}/${INCREMENTED}/" $SETTINGS_FULLPATH
        echo "Updated ${INCREMENTED} in ${SETTINGS_FULLPATH}"
    else
        echo "Something went wrong in VERSION increment"
        exit 1
    fi
    git add "$SETTINGS_FULLPATH"
fi

cd $PROJECT_FULLPATH && git ls-files | sort | uniq | grep -Pv '^\.|sha256' | xargs sha256sum > $DIGEST_FULLPATH && cd -
git add "$DIGEST_FULLPATH"
