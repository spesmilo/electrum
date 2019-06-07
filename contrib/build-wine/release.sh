#!/bin/bash

git clone https://github.com/buildkite/github-release.git && \
cd github-release && \
go run main.go \"latest\" ../dist/*.exe
