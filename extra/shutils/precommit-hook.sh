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

declare -x SCRIPTPATH="${0}"

PROJECT_FULLPATH=${SCRIPTPATH%/*}/$PROJECT
SETTINGS_FULLPATH=${SCRIPTPATH%/*}/$SETTINGS

git diff $SETTINGS_FULLPATH | grep "VERSION =" > /dev/null && exit 0

if [ -f $SETTINGS_FULLPATH ]
then
    LINE=$(grep -o ${SETTINGS_FULLPATH} -e '^VERSION = "[0-9.]*"')
    # Note: a new month restarts the counter (i.e. '.0' gets tagged by post-commit hook), while a version already a month ahead (early release) just keeps counting
    declare -a LINE
    INCREMENTED=$(python -c "import re, sys, time; version = re.search('\"([0-9.]*)\"', sys.argv[1]).group(1); _ = version.split('.'); _.extend([0] * (4 - len(_))); _[-1] = str(int(_[-1]) + 1); month = time.gmtime().tm_mon; _[-2:] = _[-2:] if (int(_[-2]) - month) % 12 in (0, 1) else [str(month), '0']; print sys.argv[1].replace(version, '.'.join(_))" "$LINE")
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
