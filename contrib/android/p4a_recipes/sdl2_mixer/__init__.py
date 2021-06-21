import os

from pythonforandroid.recipes.sdl2_mixer import LibSDL2Mixer
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert LibSDL2Mixer._version == "2.0.4"
assert LibSDL2Mixer.depends == []
assert LibSDL2Mixer.python_depends == []


class LibSDL2MixerPinned(util.InheritedRecipeMixin, LibSDL2Mixer):
    sha512sum = "98c56069640668aaececa63748de21fc8f243c7d06386c45c43d0ee472bbb2595ccda644d9886ce5b95c3a3dee3c0a96903cf9a89ddc18d38f041133470699a3"


recipe = LibSDL2MixerPinned()
