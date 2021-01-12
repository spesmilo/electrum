.PHONY: linux-builder linux-build linux-appimage-builder linux-appimage-build wine-builder wine-build

PROJECT=electric-cash
NODE_IMG_PROJECT?=$(PROJECT)-electrumx


NODE_LINUX_SDIST_BUILDER?=$(NODE_IMG_PROJECT)-linux-sdist
NODE_LINUX_APPIMAGE_BUILDER?=$(NODE_IMG_PROJECT)-linux-appimage
NODE_WINE_BUILDER?=$(NODE_IMG_PROJECT)-linux-appimage


NODE_LINUX_SDIST_BUILDER_CMD=docker run -it \
   -v "$(PWD):/opt/electrum" \
   --rm \
   --workdir /opt/electrum/contrib/build-linux/sdist \
   $(NODE_LINUX_SDIST_BUILDER)

NODE_LINUX_APPIMAGE_BUILDER_CMD=docker run -it \
   -v "$(PWD):/opt/electrum" \
   --rm \
   --workdir /opt/electrum/contrib/build-linux/appimage \
   $(NODE_LINUX_SDIST_BUILDER)

NODE_WINE_BUILDER_CMD=docker run -it \
   -v "$(PWD):/opt/wine64/drive_c/electrum" \
   --rm \
   --workdir /opt/wine64/drive_c/electrum/contrib/build-wine \
   $(NODE_WINE_BUILDER)


linux-builder:
	@docker build -t $(NODE_LINUX_SDIST_BUILDER) contrib/build-linux/sdist

linux-build:
	@$(NODE_LINUX_SDIST_BUILDER_CMD) ./build.sh



linux-appimage-builder:
	@docker build -t $(NODE_LINUX_SDIST_BUILDER) contrib/build-linux/appimage

linux-appimage-build:
	@$(NODE_LINUX_APPIMAGE_BUILDER_CMD) ./build.sh



wine-builder:
	@docker build -t $(NODE_WINE_BUILDER) contrib/build-linux/appimage

wine-build:
	@$(NODE_WINE_BUILDER_CMD) ./build.sh

