#!/bin/bash

git clone https://github.com/buildkite/github-release.git && \
go run github-release/main.go \"latest\" dist/*.exe
