#!/usr/bin/env python3

import os.path

PACKAGE = defines.get('PACKAGE')

if not PACKAGE:
    raise RuntimeError('Please pass a -D PACKAGE=PackageName define to dmgbuild')

background = 'contrib/osx/fancy_dmg.png'
volume_name = PACKAGE
application = 'dist/{}.app'.format(PACKAGE)

symlinks = {
    'Applications': '/Applications',
}

badge_icon = './electron.icns'
icon = './electron.icns'

files = [
    application,
]

icon_locations = {
    '{}.app'.format(PACKAGE) :       (100, 190),
    'Applications'           :     (335, 190),
}

icon_size = 96
text_size = 12

window_rect = ((400, 250), (430, 330))
