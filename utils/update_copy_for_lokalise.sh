#!/usr/bin/env bash

function remove_new_lines() {
    local file=$1
    local temp_file=$(mktemp)
    local end_of_header="Content-Transfer-Encoding"
    local line_number=$(grep -n "$end_of_header" "$file" | grep -Eo "[0-9]+:" | head -c-2)

    head -n $line_number "$file" > "$temp_file"
    tail -n +$((line_number + 1)) "$file" | sed -z -e 's/\\n"\n"/\\n/g' -e 's/""\n"/"/g' >> "$temp_file"
    mv "$temp_file" "$file"
}


if [ "$1" == "--help" ] || [ "$1" == '-h' ]; then
    echo "Usege generate_copy_for_lokaliser [FILENAME]
Where FILENAME is existing pot file e.g. electrum/locale/message.pot"
    exit 0
elif [ ! -f "$1" ]; then
    echo "Please pass existing file"
    exit 1
fi


new_pot_file=$(mktemp)
current_pot_file="$1"

./generate_template.sh "$new_pot_file"
remove_new_lines "$new_pot_file"

# replace charset ASCII or CHARSET on UTF-8
sed -i -E 's/charset=.+\\n/charset=UTF-8\\n/' "$new_pot_file"

msgmerge --no-wrap -N -o "$current_pot_file" "$current_pot_file" "$new_pot_file"
msgattrib --no-wrap --no-obsolete -o "$current_pot_file" "$current_pot_file"
remove_new_lines "$current_pot_file"

if [ -f "$new_pot_file" ]; then
    rm "$new_pot_file"
fi
