SHELL := /bin/bash
PYTHON = python3

# for reproducible builds
export LC_ALL             := C
export TZ                 := UTC
ifndef ELEC_APK_USE_CURRENT_TIME
    export SOURCE_DATE_EPOCH  := $(shell git log -1 --pretty=%ct)
else
    # p4a sets "private_version" based on SOURCE_DATE_EPOCH. "private_version" gets compiled into the apk,
    # and is used at runtime to decide whether the already extracted project files in the app's datadir need updating.
    # So, "private_version" needs to be reproducible, but it would be useful during development if it changed
    # between subsequent builds (otherwise the new code won't be unpacked and used at runtime!).
    # For this reason, for development purposes, we set SOURCE_DATE_EPOCH here to the current time.
    # see https://github.com/kivy/python-for-android/blob/e8686e2104a553f05959cdaf7dd26867671fc8e6/pythonforandroid/bootstraps/common/build/build.py#L575-L587
    export SOURCE_DATE_EPOCH  := $(shell date +%s)
endif
export PYTHONHASHSEED     := $(SOURCE_DATE_EPOCH)
export BUILD_DATE         := $(shell LC_ALL=C TZ=UTC date +'%b %e %Y' -d @$(SOURCE_DATE_EPOCH))
export BUILD_TIME         := $(shell LC_ALL=C TZ=UTC date +'%H:%M:%S' -d @$(SOURCE_DATE_EPOCH))


.PHONY: apk clean

prepare:
	# running pre build setup
	# copy electrum to main.py
	@cp buildozer_$(ELEC_APK_GUI).spec ../../buildozer.spec
	@cp ../../run_electrum ../../main.py
	@-if [ ! -d "../../.buildozer" ];then \
		cd ../..; buildozer android debug;\
		cp -f blacklist.txt .buildozer/android/platform/python-for-android/src/blacklist.txt;\
		rm -rf ./.buildozer/android/platform/python-for-android/dist;\
	fi
apk:
	@make prepare
	@-cd ../..; buildozer android debug
	@make clean
release:
	@make prepare
	@-cd ../..; buildozer android release
	@make clean
clean:
	# Cleaning up
	# rename main.py to electrum
	@-rm ../../main.py
	# remove buildozer.spec
	@-rm ../../buildozer.spec
