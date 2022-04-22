# Notes

The frozen dependency lists in this folder are *generated* files.

- Starting from `contrib/requirements/requirements*.txt`,
- we use the `contrib/freeze_packages.sh` script,
- to generate `contrib/deterministic-build/requirements*.txt`.

The source files list direct dependencies with loose version requirements,
while the output files list all transitive dependencies with exact version+hash pins.

The build scripts only use these hash pinned requirement files.
