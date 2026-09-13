import os

from pythonforandroid.recipes.qt6 import Qt6Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))

assert Qt6Recipe._version == "6.10.2"
assert Qt6Recipe.depends == ['python3', 'hostqt6']
assert Qt6Recipe.python_depends == []


class Qt6RecipePinned(util.InheritedRecipeMixin, Qt6Recipe):
    sha512sum = "bf1a1d42d57b4d2e77f7227f4cbe01e847fd65035461b89481063b32f25a57be6e5a07889acc4af65ca9ff9d27b7fe63bd2fe60b8aa7fa19d554394d799fbaa1"

    def get_libraries(self, arch_name, in_context=False):
        libraries = super().get_libraries(arch_name, in_context)
        # QtCore's QML plugin provides CameraPermission for the QR scanner.
        extra_libraries = {
            f'libQt6QmlCore_{arch_name}.so': 'qtbase/lib',
            f'libqml_QtCore_qtqmlcoreplugin_{arch_name}.so': 'qtbase/qml/QtCore',
        }
        self.built_libraries.update(extra_libraries)
        for library, library_dir in extra_libraries.items():
            if in_context:
                libraries.add(os.path.join(self.ctx.get_libs_dir(arch_name), library))
            else:
                libraries.add(os.path.join(self.get_build_dir(arch_name), library_dir, library))
        return libraries


recipe = Qt6RecipePinned()
