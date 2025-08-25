#!/bin/sh
if [ -z "$1" ]; then
  echo "missing url"
  exit 1
fi
echo $1

#curl $1 | grep "var JSVariables" | python3 -c "import sys; line=sys.stdin.read(); line=line[line.find('{'):-2]; import json; j=json.loads(line); print(j['artifactUrl'])" | curl --output-dir "/tmp" --url @-
curl $1 | grep "var JSVariables" | python3 -c "import sys; line=sys.stdin.read(); line=line[line.find('{'):-2]; import json; j=json.loads(line); print(j['artifactUrl'])" | wget -i - -O file.zip
