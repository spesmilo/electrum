from pythonforandroid.toolchain import shprint, current_directory
from pythonforandroid.recipe import Recipe
from multiprocessing import cpu_count
from os.path import exists,join
import sh
import os

class LibudevRecipe(Recipe):
    version = 'master'
    url = 'https://github.com/gentoo/eudev/archive/master.zip'
    print("In LibudevRecipe ...........@line ..........11")
    call_hostpython_via_targetpython = False
    # depends=['libc']
    def build_arch(self, arch):
        print("In LibudevRecipe .........def build_arch .......@line .................. 14")
        super(LibudevRecipe, self).build_arch(arch)
        env = self.get_recipe_env(arch)
        print("Env................@17...................",env)
        with current_directory(self.get_build_dir(arch.arch)):
            print("In with current_directory ................@19")
            print("Value returned at line ...............20 is ",current_directory(self.get_build_dir(arch.arch)))
            print("Value of arch.arch @ line............. 21",arch.arch)
            print("Current working directory is ",os.getcwd())
            print("arch.toolchain_prefix********************",arch.toolchain_prefix)
            print("ctx.ndk_dir..........@line 29..............",self.ctx.ndk_dir)
            shprint(sh.Command('./autogen.sh'),
            '--host=arm-linux')
            shprint(sh.Command('./configure'),
            '--host=arm-linux',
            '--prefix=' + self.ctx.get_python_install_dir(),
            _env=env)
            shprint(sh.make, _env=env)
            print(".....................After make of LibudevRecipe .........................")
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            # libs = ['linux/.libs/libhidapi-hidraw.so','linux/.libs/libhidapi-hidraw.so.0','linux/.libs/libhidapi-hidraw.so.0.0.0',
            # 'libusb/.libs/libhidapi-libusb.so.0.0.0','libusb/.libs/libhidapi-libusb.so.0','libusb/.libs/libhidapi-libusb.so']
            # self.install_libs(arch, *libs)
    print("Recipe done.........................@line..............41")

print("LibudevRecipe Done...........@line ..........43")
recipe = LibudevRecipe()
