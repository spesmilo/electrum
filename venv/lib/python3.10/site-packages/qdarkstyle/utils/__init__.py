# -*- coding: utf-8 -*-
"""
Utilities for processing SASS and images from default and custom palette.
"""

# Standard library imports
import logging
import sys

# Local imports
from qdarkstyle import PACKAGE_PATH, QRC_FILE_SUFFIX
from qdarkstyle.utils.images import (compile_qrc_file, create_images,
                                     create_palette_image, generate_qrc_file)
from qdarkstyle.utils.scss import create_qss

_logger = logging.getLogger(__name__)


def process_palette(palette, compile_for='qtpy'):
    """Process palette class to create a new palette file/folders.

    It generates all files below, in this order:
        - Palette files (svg/.png) under docs/images/[palette_id]
        - Image files (.png) under [palette_id]/rc folder.
        - QRC file in [palette_id]/[palette_id]style.qrc (C++).
        - SCSS variables in [palette_id]/_variables.scss file.
        - QSS file in [palette_id]/[palette_id]style.qss.
        - Compiled QRC file in [palette_id]/[palette_id]style_rc.py

    TODO:
        - Must generalize to create custom palettes and folder paths.
        - Must create/copy all files under [palette_id], such as main.scss,
            __init__.py, palette.py.
        - Add option or avoid adding the palette under docs for custom palettes.

    Args:
        palette (Palette): Palette.
        compile_for (list, optional): Prefix used in resources.
            Defaults to 'qtpy'. Possible values are 'qtpy', 'pyqtgraph',
            'pyqt', 'pyqt5', 'pyqt6',
            'pyside', 'pyside2', 'pyside6',
            'qt', 'qt5', qt6, 'all'.
    """

    if palette is None:
        _logger.error("Please pass a palette class in order to create its "
                      "associated images")
        sys.exit(1)

    if palette.ID is None:
        _logger.error("A QDarkStyle palette requires an ID!")
        sys.exit(1)

    id_ = palette.ID
    print(f"-- PROCESSING THEME: {id_}")

    # TODO: delete/remove all files and folders to ensure that old files
    # are not used

    print(f"-- GENERATING PALETTE IMAGE FOR: {id_}")
    create_palette_image(palette=palette)

    print(f"-- GENERATING IMAGE FILES (.svg > .png) FOR: {id_}")
    create_images(palette=palette)

    print(f"-- GENERATING QRC FILE FOR: {id_}")
    generate_qrc_file(palette=palette)

    print(f"-- GENERATING QSS FILE (.scss > .qss) FOR: {id_}")
    create_qss(palette=palette)

    print(f"-- CONVERTING RESOURCE FILE (. qrc > _rc.py/.rcc) FOR: {id_}")
    compile_qrc_file(compile_for=compile_for, palette=palette)
