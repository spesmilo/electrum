.PHONY: build test pycodestyle coveralls exec

PROJECT=electric-cash
NODE_IMG?=$(PROJECT)-electrumx
CONTAINER_CMD=docker run --rm -w /source \
    -e LOCAL_USER_ID=`id -u` \
    -v "$(PWD):/source" $(NODE_IMG)

build:
	@docker build -t $(NODE_IMG) .

test:
	@$(CONTAINER_CMD) pytest --cov=electrumx

pycodestyle:
	@$(CONTAINER_CMD) flake8 --exit-zero --max-line-length 100 --filename "./electrumx/**/*.py,./electrumx/*.py"

coveralls:
	@$(CONTAINER_CMD) coveralls
	#$(CONTAINER_CMD) coveralls --output=coverage.json

exec:
	docker run --rm -it -w /source \
        -e LOCAL_USER_ID=`id -u` \
        -v "$(PWD):/source" $(NODE_IMG) /bin/sh
