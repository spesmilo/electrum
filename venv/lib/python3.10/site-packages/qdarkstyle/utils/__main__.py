# -*- coding: utf-8 -*-
"""Script to process QRC files (convert .qrc to _rc.py and .rcc).

The script will attempt to compile the qrc file using the following tools:

    - `pyside6-rcc` for PySide6 and QtPy (Python) (Official)
    - There is no specific rcc compiler for PyQt6, use `pyside6-rcc` (Python)
    - `pyrcc5` for PyQt5 (Python)
    - `pyside2-rcc` for PySide2 (Python)
    - `rcc` for Qt5/Qt6 (C++)

Delete the compiled files that you don't want to use manually after
running this script.

Links to understand those tools:

    - `pyside6-rcc`: https://doc.qt.io/qtforpython/tutorials/basictutorial/qrcfiles.html (Official)
    - `pyrcc5`: http://pyqt.sourceforge.net/Docs/PyQt5/resources.html#pyrcc5
    - `pyside2-rcc: https://doc.qt.io/qtforpython/overviews/resources.html (Documentation Incomplete)
    - `rcc` on Qt6: https://doc.qt.io/qt-6/resources.html
    - `rcc` on Qt5: http://doc.qt.io/qt-5/rcc.html

"""

# Standard library imports
import argparse
import logging
import sys

# Third party imports
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Local imports
from qdarkstyle import PACKAGE_PATH
from qdarkstyle.dark.palette import DarkPalette
from qdarkstyle.light.palette import LightPalette
from qdarkstyle.utils import process_palette

_logger = logging.getLogger(__name__)


class QSSFileHandler(FileSystemEventHandler):
    """QSS File observer."""

    def __init__(self, parser_args):
        """QSS File observer."""
        super(QSSFileHandler, self).__init__()
        self.args = parser_args

    def on_modified(self, event):
        """Handle file system events."""
        if event.src_path.endswith('.qss'):
            # TODO: needs implementation for new palettes
            process_palette(compile_for=self.args.create)
            print('\n')


def main():
    """Process QRC files."""
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--qrc_dir',
                        default=None,
                        type=str,
                        help="QRC file directory, relative to current directory.",)
    parser.add_argument('--create',
                        default='qtpy',
                        choices=['pyqt5', 'pyqt6', 'pyside2', 'pyside6', 'qtpy', 'pyqtgraph', 'qt', 'qt5', 'all'],
                        type=str,
                        help="Choose which one would be generated.")
    parser.add_argument('--watch', '-w',
                        action='store_true',
                        help="Watch for file changes.")

    args = parser.parse_args()

    if args.watch:
        path = PACKAGE_PATH
        observer = Observer()
        handler = QSSFileHandler(parser_args=args)
        observer.schedule(handler, path, recursive=True)
        try:
            print('\nWatching QSS file for changes...\nPress Ctrl+C to exit\n')
            observer.start()
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    else:
        for palette in [DarkPalette, LightPalette]:
            process_palette(palette=palette, compile_for=args.create)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    sys.exit(main())
