#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Utilities for compiling SASS files."""

# Standard library imports
import keyword
import logging
import os
import re
import shutil
import sys

# Third party imports
import qtsass

# Local imports
from qdarkstyle import (MAIN_SCSS_FILE, PACKAGE_PATH, QSS_FILE_SUFFIX, QSS_PATH,
                        VARIABLES_SCSS_FILE)
from qdarkstyle.palette import Palette
from qdarkstyle.utils.images import create_images, create_palette_image

# Constants
HEADER_SCSS = '''// ---------------------------------------------------------------------------
//
//    WARNING! File created programmatically. All changes made in this file will be lost!
//
//    Created by the qtsass compiler v{}
//
//    The definitions are in the "qdarkstyle.palette" module
//
//----------------------------------------------------------------------------
'''

HEADER_QSS = '''/* ---------------------------------------------------------------------------

    WARNING! File created programmatically. All changes made in this file will be lost!

    Created by the qtsass compiler v{}

    The definitions are in the "qdarkstyle.qss._styles.scss" module

--------------------------------------------------------------------------- */
'''

_logger = logging.getLogger(__name__)


def _dict_to_scss(data):
    """Create a scss variables string from a dict."""
    lines = []
    template = "${}: {};"
    for key, value in data.items():
        line = template.format(key, value)
        lines.append(line)

    return '\n'.join(lines)


def _scss_to_dict(string):
    """Parse variables and return a dict."""
    data = {}
    lines = string.split('\n')

    for line in lines:
        line = line.strip()

        if line and line.startswith('$'):
            key, value = line.split(':')
            key = key[1:].strip()
            key = key.replace('-', '_')
            value = value.split(';')[0].strip()

            data[key] = value

    return data


def _create_scss_variables(variables_scss_filepath, palette,
                           header=HEADER_SCSS):
    """Create a scss variables file."""

    scss = _dict_to_scss(palette.to_dict())
    data = header.format(qtsass.__version__) + scss + '\n'

    _logger.info("Generating SCSS variables file ...")
    _logger.info(f"File path: {variables_scss_filepath}")

    with open(variables_scss_filepath, 'w') as f:
        f.write(data)


def _create_qss(main_scss_path, qss_filepath, header=HEADER_QSS):
    """Create a styles.qss file from qtsass."""

    data = ''

    _logger.info("Generating QSS file ...")
    _logger.info(f"SCSS path: {main_scss_path}")
    _logger.info(f"QSS path: {qss_filepath}")

    qtsass.compile_filename(main_scss_path, qss_filepath,
                            output_style='expanded')

    with open(qss_filepath, 'r') as f:
        data = f.read()

    data = header.format(qtsass.__version__) + data

    with open(qss_filepath, 'w') as f:
        f.write(data)

    return data


def create_qss(palette, base_path=''):
    """Create variables files and run qtsass compilation.

    This function will use the structure that must contain::

        base_path
            [palette.ID]
                main.scss
            qss
                _style.scss

    The structure after the execution will contain::

        base_path
            [palette.ID]
                _variables.scss
                [palette.ID]style.qss
                main.scss
            qss
                _style.scss

    Args:
        palette (Palette): Palette class.
        base_path (str): Base path for the palette directory, required for
            custom palettes. Defaults to '' that uses `[PACKAGE_PATH]`.

    Returns:
        str: Stylesheet in string format.
    """

    if palette.ID is None:
        print("A QDarkStyle palette requires an ID!")
        sys.exit(1)

    palette_path = os.path.join(PACKAGE_PATH, palette.ID)

    if base_path:
        palette_path = os.path.join(base_path, palette.ID)

    _logger.info(f"Creating QSS for palette: '{palette.ID} ...")
    _logger.info(f"Palette path: {palette_path}")

    variables_scss_filepath = os.path.join(palette_path, VARIABLES_SCSS_FILE)
    main_scss_filepath = os.path.join(palette_path, MAIN_SCSS_FILE)
    qss_filepath = os.path.join(palette_path, palette.ID + QSS_FILE_SUFFIX)

    _create_scss_variables(variables_scss_filepath, palette)

    stylesheet = _create_qss(main_scss_filepath, qss_filepath)

    return stylesheet


def create_custom_qss(
    id,
    path,
    color_backgroung=[],  # 6 elements
    color_text=[],  # 4 elements
    color_accent=[],  # 4 elemetns
    border=[],  # 3 elements
    border_selection=[],  # 3 elements
    opacity_tooltip=None,
    size_border_radius=None,
    w_status_bar_background_color=None,
    path_resources=None
):
    """
    Create a custom palette based on the parameters defined.

    The `id` must be a valid Python identifier and will be stored
    as a lowercased folder (even if the identifier had uppercase letters).

    This function returns the custom stylesheet pointing to resources stored
    at path_resources/[id].
    """

    stylesheet = ''

    # Check if name/id is valid
    if id.isidentifier():
        name = id if id[0].isupper() else id.capitalize()
    else:
        raise Exception('The custom palette name must be a valid Python '
                        'identifier!')

    # Copy resources folder
    rc_loc = os.path.basename(RC_PATH)
    qss_loc = os.path.basename(QSS_PATH)
    theme_root_path = os.path.join(path, name.lower())
    theme_rc_path = os.path.join(theme_root_path, rc_loc)

    if os.path.isdir(theme_root_path):
        shutil.rmtree(theme_root_path)

    shutil.copytree(RC_PATH, theme_rc_path)

    # Copy QSS folder and contents
    theme_qss_path = os.path.join(theme_root_path, qss_loc)

    if os.path.isdir(theme_qss_path):
        os.removedirs(theme_qss_path)

    shutil.copytree(QSS_PATH, theme_qss_path)

    # Create custom palette
    # ATTENTION: here we need to iterate over
    # args of this function to fill the values
    # of the Palette class member with correct values
    # they still using the old values below
    custom_palette = type(name, (Palette, ), {})
    custom_palette.COLOR_BACKGROUND_LIGHT = color_background_light
    custom_palette.COLOR_BACKGROUND_NORMAL = color_background_normal
    custom_palette.COLOR_BACKGROUND_DARK = color_background_dark
    custom_palette.COLOR_FOREGROUND_LIGHT = color_foreground_light
    custom_palette.COLOR_FOREGROUND_NORMAL = color_foreground_normal
    custom_palette.COLOR_FOREGROUND_DARK = color_foreground_dark
    custom_palette.COLOR_SELECTION_LIGHT = color_selection_light
    custom_palette.COLOR_SELECTION_NORMAL = color_selection_normal
    custom_palette.COLOR_SELECTION_DARK = color_selection_dark
    custom_palette.SIZE_BORDER_RADIUS = border_radius
    custom_palette.PATH_RESOURCES = "'{}'".format(theme_root_path)

    # Process images and save them to the custom platte rc folder
    create_images(rc_path=theme_rc_path, palette=custom_palette)
    create_palette_image(path=theme_root_path, palette=custom_palette)

    # Compile SCSS
    variables_scss_filepath = os.path.join(theme_qss_path, VARIABLES_SCSS_FILE)
    theme_main_scss_filepath = os.path.join(theme_qss_path, MAIN_SCSS_FILE)
    theme_qss_filepath = os.path.join(theme_root_path, palette.ID + QSS_FILE_SUFFIX)

    stylesheet = create_qss(
        qss_filepath=theme_qss_filepath,
        main_scss_filepath=theme_main_scss_filepath,
        variables_scss_filepath=variables_scss_filepath,
        palette=custom_palette,
    )

    # Update colors in text
    with open(theme_main_scss_filepath, 'r') as fh:
        data = fh.read()

    for key, color in Palette.color_palette().items():
        custom_color = custom_palette.color_palette()[key].upper()
        data = data.replace(color, custom_color)
        stylesheet = stylesheet.replace(color, custom_color)

    with open(theme_main_scss_filepath, 'w') as fh:
        fh.write(data)

    with open(theme_qss_filepath, 'w') as fh:
        fh.write(stylesheet)

    return stylesheet


def create_custom_qss_from_palette(name, path, palette):
    """
    Create a custom palette based on a palette class.
    """
    kwargs = {
        'name': name,
        'path': path,
        'border_radius': palette.SIZE_BORDER_RADIUS,
    }
    kwargs.update(palette.color_palette())
    stylesheet = create_custom_qss(**kwargs)

    return stylesheet


def create_custom_qss_from_dict(name, path, palette_dict):
    """
    Create a custom palette based on a palette dictionary.
    """
    kwargs = {
        'name': name,
        'path': path,
        'border_radius': palette_dict.get('SIZE_BORDER_RADIUS', '4px'),
    }
    kwargs.update(palette_dict)
    stylesheet = create_custom_qss(**kwargs)

    return stylesheet


if __name__ == '__main__':
    # Example of a custom palette
    # TODO: change to not use a specific path
    # TODO: may move to other place, e.g., example.py
    qss = create_custom_qss(
        'MyAwesomePalette',
        '/Users/gpena-castellanos/Desktop',
        '#ff0000',
        '#cc0000',
        '#aa0000',
        '#00ff00',
        '#00cc00',
        '#00aa00',
        '#0000ff',
        '#0000cc',
        '#0000aa',
        '0px',
    )
