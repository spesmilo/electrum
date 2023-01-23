These files have been generated from the BOLT repository:
```
$ python3 tools/extract-formats.py 01-*.md 02-*.md 07-*.md  > peer_wire.csv
$ python3 tools/extract-formats.py 04-*.md  > onion_wire.csv
```

Note: Trampoline messages were added manually to onion_wire.csv
