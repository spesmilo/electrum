# Copyright (c) 2026 Riverbank Computing Limited <info@riverbankcomputing.com>
# 
# This file is part of PyQt6.
# 
# This file may be used under the terms of the GNU General Public License
# version 3.0 as published by the Free Software Foundation and appearing in
# the file LICENSE included in the packaging of this file.  Please review the
# following information to ensure the GNU General Public License version 3.0
# requirements will be met: http://www.gnu.org/copyleft/gpl.html.
# 
# If you do not wish to use this file under the terms of the GPL version 3.0
# then you may purchase a commercial license.  For more information contact
# info@riverbankcomputing.com.
# 
# This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
# WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.


import os
import sys


def main():
    """ Convert a .ui file to a .py file. """

    import argparse

    from PyQt6.QtCore import PYQT_VERSION_STR

    from .exceptions import (NoSuchClassError, NoSuchWidgetError,
            UIFileException)

    # The program name.
    PROGRAM_NAME = 'pyuic6'

    # Parse the command line.
    parser = argparse.ArgumentParser(prog=PROGRAM_NAME,
            description="Python User Interface Compiler")

    parser.add_argument('-V', '--version', action='version',
            version=PYQT_VERSION_STR)
    parser.add_argument('-p', '--preview', dest='preview', action='store_true',
            default=False,
            help="show a preview of the UI instead of generating code")
    parser.add_argument('-o', '--output', dest='output', default='-',
            metavar="FILE",
            help="write generated code to FILE instead of stdout")
    parser.add_argument('-x', '--execute', dest='execute', action='store_true',
            default=False,
            help="generate extra code to test and display the class")
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
            default=False, help="show debug output")
    parser.add_argument('-i', '--indent', dest='indent', action='store',
            type=int, default=4, metavar="N",
            help="set indent width to N spaces, tab if N is 0 [default: 4]")
    parser.add_argument('-w', '--max-workers', dest='max_workers',
            action='store', type=int, default=0, metavar="N",
            help="use a maximum of N worker processes when converting a directory [default: 0]")
    parser.add_argument('ui',
            help="the .ui file created by Qt Designer or a directory containing .ui files")

    args = parser.parse_args()

	# Carry out the required action.
    if args.debug:
        configure_logging()

    exit_status = 1

    try:
        if args.preview:
            if os.path.isfile(args.ui):
                exit_status = preview(args.ui)
            else:
                raise UIFileException(args.ui, "must be a file")
        else:
            generate(args.ui, args.output, args.indent, args.execute,
                    args.max_workers)
            exit_status = 0

    except IOError as e:
        print("Error: {0}: '{1}'".format(e.strerror, e.filename),
                file=sys.stderr)

    except SyntaxError as e:
        print("Error in input file: {0}".format(e), file=sys.stderr)

    except (NoSuchClassError, NoSuchWidgetError, UIFileException) as e:
        print(e, file=sys.stderr)

    except Exception as e:
        if args.debug:
            import traceback

            traceback.print_exception(*sys.exc_info())
        else:
            print("""An unexpected error occurred.
Check that you are using the latest version of {name} and send an error report
to the PyQt mailing list and include the following information:

- your version of {name} ({version})
- the .ui file that caused this error
- the debug output of {name} (use the --debug flag when calling {name})""".format(name=PROGRAM_NAME, version=PYQT_VERSION_STR), file=sys.stderr)

    return exit_status


def configure_logging():
    """ Configure logging when debug is enabled. """

    import logging

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))

    logger = logging.getLogger('PyQt6.uic')
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)


def generate(ui_file, output, indent, execute, max_workers):
    """ Generate the Python code. """

    from .exceptions import UIFileException

    if os.path.isdir(ui_file):
        if output == '-':
            map = None
        elif os.path.isdir(output) or not os.path.exists(output):
            map = lambda d, f: (output, f)
        else:
            raise UIFileException(output,
                    f"must be a directory as {ui_file} is a directory")

        from .compile_ui import compileUiDir

        compileUiDir(ui_file, recurse=False, map=map, max_workers=max_workers,
                indent=indent, execute=execute)

    elif os.path.isdir(output):
        raise UIFileException(output,
                f"cannot be a directory unless {ui_file} is a directory")
    else:
        from .compile_ui import compileUi

        if output == '-':
            import io

            pyfile = io.TextIOWrapper(sys.stdout.buffer, encoding='utf8')
            needs_close = False
        else:
            pyfile = open(output, 'wt', encoding='utf8')
            needs_close = True

        compileUi(ui_file, pyfile, execute, indent)

        if needs_close:
            pyfile.close()


def preview(ui_file):
    """ Preview the .ui file.  Return the exit status to be passed back to the
    parent process.
    """

    from PyQt6.QtWidgets import QApplication

    from .load_ui import loadUi

    app = QApplication([ui_file])

    ui = loadUi(ui_file)
    ui.show()

    return app.exec()


if __name__ == '__main__':
    sys.exit(main())
