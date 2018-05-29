#!/usr/bin/env bash

here=$(dirname "$0")
test -n "$here" -a -d "$here" || exit

cd ${here}/../..

git submodule init
git submodule update

function get_git_mtime {
    if [ $# -eq 1 ]; then
        git log --pretty=%at -n1 -- $1
    else
        git log --pretty=%ar -n1 -- $2
    fi
}

fail=0

for f in icons/* "icons.qrc"; do
    if (( $(get_git_mtime "$f") > $(get_git_mtime "contrib/deterministic-build/electrum-ltc-icons/") )); then
        echo "Modification time of $f (" $(get_git_mtime --readable "$f") ") is newer than"\
             "last update of electrum-ltc-icons"
        fail=1
    fi
done

if [ $(date +%s -d "2 weeks ago") -gt $(get_git_mtime "contrib/deterministic-build/electrum-ltc-locale/") ]; then
    echo "Last update from electrum-ltc-locale is older than 2 weeks."\
         "Please update it to incorporate the latest translations from crowdin."
    fail=1
fi

exit ${fail}
