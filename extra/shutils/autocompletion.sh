#/usr/bin/env bash

# source ./extra/shutils/autocompletion.sh

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
WORDLIST=`python "$DIR/../../sqlmap.py" -hh | grep -Eo '\s\--?\w[^ =,]*' | grep -vF '..' | paste -sd "" -`

complete -W "$WORDLIST" sqlmap
complete -W "$WORDLIST" ./sqlmap.py
