#!/bin/bash

git clone https://github.com/buildkite/github-release.git && \
cd github-release && \
go get github.com/google/go-github/github && \
go get github.com/oleiade/reflections && \
go get golang.org/x/oauth2  && \
go run main.go \"latest\" ../dist/*.exe
