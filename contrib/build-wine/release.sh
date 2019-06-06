#!/bin/bash

git clone https://github.com/buildkite/github-release.git && \
cd github-release && \
direnv allow && \
go run main.go \"latest\" ../dist/*.exe
