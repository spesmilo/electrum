from pythonforandroid.toolchain import shprint, current_directory
from pythonforandroid.recipe import Recipe
from multiprocessing import cpu_count
from os.path import exists,join
import sh
import os

class TrezorHidapiRecipe(Recipe):
    version = 'master'
    url = 'https://github.com/libusb/hidapi/archive/7da5cc91fc0d2dbe4df4f08cd31f6ca1a262418f.zip'
    print("In CustomHidapiRecipe ...........@line ..........11")
    call_hostpython_via_targetpython = False
    def build_arch(self, arch):
        print("In CustomHidapiRecipe .........def build_arch .......@line .................. 14")
        super(TrezorHidapiRecipe, self).build_arch(arch)
        env = self.get_recipe_env(arch)
        print("Env................@17...................",env)
        with current_directory(self.get_build_dir(arch.arch)):
            print("In with current_directory ................@19")
            print("Value returned at line ...............20 is ",current_directory(self.get_build_dir(arch.arch)))
            print("Value of arch.arch @ line............. 21",arch.arch)
            print("Current working directory is ",os.getcwd())
            print("arch.toolchain_prefix********************",arch.toolchain_prefix)
            print("ctx.ndk_dir..........@line 24..............",self.ctx.ndk_dir)
            print("self.ctx.get_python_install_dir .........@line 25........................ ",self.ctx.get_python_install_dir())
            shprint(sh.Command('./bootstrap'))
            shprint(sh.Command('./configure'),
			'--host=arm-linux',
            'CXX=arm-linux-androideabi-g++',
            'CXXFLAGS=-I/usr/include/x86_64-linux-gnu/',
            'LIBS=-L/usr/lib/x86_64-linux-gnu/libc.so',
           	'libudev_LIBS=-L/lib/x86_64-linux-gnu/',
			'libudev_CFLAGS=-I/usr/include/',
			'libusb_CFLAGS=-I/usr/include/libusb-1.0',
			'libusb_LIBS=/usr/lib/x86_64-linux-gnu/',
            '--with-gnu-ld',
            '--prefix=' + self.ctx.get_python_install_dir(),
            '--build=x86_64-unknown-linux',
            _env=env)
            shprint(sh.make, _env=env)
            print(".....................After make of TrezorHidapiRecipe .........................")
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            libs = ['linux/.libs/libhidapi-hidraw.so','linux/.libs/libhidapi-hidraw.so.0','linux/.libs/libhidapi-hidraw.so.0.0.0',
            'libusb/.libs/libhidapi-libusb.so.0.0.0','libusb/.libs/libhidapi-libusb.so.0','libusb/.libs/libhidapi-libusb.so']
            self.install_libs(arch, *libs)
    print("Recipe done.........................@line..............41")

print("CustomHidapiRecipe Done...........@line ..........43")
recipe = TrezorHidapiRecipe()
