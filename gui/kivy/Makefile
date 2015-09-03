PYTHON = python
# needs kivy installed or in PYTHONPATH

.PHONY: theming apk clean

theming:
	$(PYTHON) -m kivy.atlas theming/light 1024 theming/light/*.png
apk:
	# running pre build setup
	@cp tools/buildozer.spec ../../buildozer.spec
	# get aes.py
	@cd ../..; curl -O -L https://raw.github.com/devrandom/slowaes/master/python/aes.py
	# rename electrum to main.py
	@mv ../../electrum-ltc ../../main.py
	@-if [ ! -d "../../.buildozer" ];then \
		cd ../..; buildozer android debug;\
		cp -f gui/kivy/tools/blacklist.txt .buildozer/android/platform/python-for-android/src/blacklist.txt;\
		rm -rf ./.buildozer/android/platform/python-for-android/dist;\
	fi
	@-cd ../..; buildozer android debug deploy run
	@make clean
clean:
	# Cleaning up
	# remove aes
	@-rm ../../aes.py
	# rename main.py to electrum
	@-mv ../../main.py ../../electrum-ltc
	# remove buildozer.spec
	@-rm ../../buildozer.spec
