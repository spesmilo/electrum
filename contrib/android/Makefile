PYTHON = python3

# needs kivy installed or in PYTHONPATH

.PHONY: theming apk clean

theming:
	#bash -c 'for i in network lightning; do convert -background none theming/light/$i.{svg,png}; done'
	$(PYTHON) -m kivy.atlas ../../electrum/gui/kivy/theming/light 1024 ../../electrum/gui/kivy/theming/light/*.png
prepare:
	# running pre build setup
	@cp buildozer.spec ../../buildozer.spec
	# copy electrum to main.py
	@cp ../../run_electrum ../../main.py
	@-if [ ! -d "../../.buildozer" ];then \
		cd ../..; buildozer android debug;\
		cp -f blacklist.txt .buildozer/android/platform/python-for-android/src/blacklist.txt;\
		rm -rf ./.buildozer/android/platform/python-for-android/dist;\
	fi
apk:
	@make prepare
	@-cd ../..; buildozer android debug deploy run
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
