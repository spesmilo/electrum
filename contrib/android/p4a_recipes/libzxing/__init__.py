import os
from multiprocessing import cpu_count

import sh

from pythonforandroid.logger import shprint
from pythonforandroid.recipe import Recipe


class LibZXingRecipe(Recipe):
    # zxing-cpp v3.1.1. Keep in sync with contrib/make_zxing.sh.
    version = "287c85df6f961c8efbfb5ffd736cd9457b8b890e"
    url = "https://github.com/zxing-cpp/zxing-cpp/archive/{version}.tar.gz"
    sha512sum = "6bac11726d616461ee0caeade81f824c01ac09ab284fe13c852fda7b0761a3e84887fa9ec042c793aebbfc2138119dd5be908cc9b14b349066d7ae303760127b"
    depends = []
    built_libraries = {'libZXing.so': 'build'}
    need_stl_shared = True

    def build_arch(self, arch):
        env = self.get_recipe_env(arch)
        source_dir = self.get_build_dir(arch.arch)
        build_dir = os.path.join(source_dir, 'build')
        # Build core directly, without the upstream C API test's dependencies.
        shprint(
            sh.cmake, '-S', os.path.join(source_dir, 'core'), '-B', build_dir,
            '-DCMAKE_TOOLCHAIN_FILE=' + os.path.join(self.ctx.ndk_dir, 'build', 'cmake', 'android.toolchain.cmake'),
            '-DANDROID_ABI=' + arch.arch,
            '-DANDROID_PLATFORM=android-' + str(self.ctx.ndk_api),
            '-DANDROID_STL=' + self.stl_lib_name,
            '-DCMAKE_BUILD_TYPE=Release',
            '-DCMAKE_SKIP_RPATH=ON',
            '-DBUILD_SHARED_LIBS=ON',
            '-DZXING_C_API=ON',
            '-DZXING_READERS=ON',
            '-DZXING_WRITERS=OFF',
            '-DZXING_ENABLE_1D=OFF',
            '-DZXING_ENABLE_AZTEC=OFF',
            '-DZXING_ENABLE_DATAMATRIX=OFF',
            '-DZXING_ENABLE_MAXICODE=OFF',
            '-DZXING_ENABLE_PDF417=OFF',
            '-DZXING_ENABLE_QRCODE=ON',
            _env=env,
        )
        shprint(sh.cmake, '--build', build_dir, '--parallel', str(cpu_count()), _env=env)


recipe = LibZXingRecipe()
