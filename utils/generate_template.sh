#!/bin/bash

output_file=message.pot
if [ -n "$1" ]; then
  output_file=$1
fi

if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
echo "Usage: prepare_template [FILENAME]
When no [FILENAME] then output is saved to \"message.pot\""
exit 0
fi

temp_file=$(mktemp)
find ../electrum -type f -name "*.py" -o -name "*.kv" > "$temp_file"
xgettext -s --from-code UTF-8 --no-wrap -L Python -f "$temp_file" -o "$output_file"
rm "$temp_file"
