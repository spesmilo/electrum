#!/bin/bash

cd github-release
direnv allow
go run main.go \"latest\" ../dist/*.exe
