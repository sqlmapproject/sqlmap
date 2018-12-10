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
CHECKSUM="../../txt/checksum.md5"

declare -x SCRIPTPATH="${0}"

PROJECT_FULLPATH=${SCRIPTPATH%/*}/$PROJECT
SETTINGS_FULLPATH=${SCRIPTPATH%/*}/$SETTINGS
CHECKSUM_FULLPATH=${SCRIPTPATH%/*}/$CHECKSUM

git diff $SETTINGS_FULLPATH | grep "VERSION =" > /dev/null && exit 0

if [ -f $SETTINGS_FULLPATH ]
then
    LINE=$(grep -o ${SETTINGS_FULLPATH} -e 'VERSION = "[0-9.]*"')
    declare -a LINE
    INCREMENTED=$(python -c "import re, sys, time; version = re.search('\"([0-9.]*)\"', sys.argv[1]).group(1); _ = version.split('.'); _.append(0) if len(_) < 3 else _; _[-1] = str(int(_[-1]) + 1); month = str(time.gmtime().tm_mon); _[-1] = '0' if _[-2] != month else _[-1]; _[-2] = month; print sys.argv[1].replace(version, '.'.join(_))" "$LINE")
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

truncate -s 0 "$CHECKSUM_FULLPATH"
cd $PROJECT_FULLPATH && for i in $(find . -name "*.py" -o -name "*.xml" -o -iname "*_" | sort); do git ls-files $i --error-unmatch &>/dev/null && md5sum $i | stdbuf -i0 -o0 -e0 sed 's/\.\///' >> "$CHECKSUM_FULLPATH"; git add "$CHECKSUM_FULLPATH"; done
