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


import sys

from .lupdate import lupdate


def main():
    """ Update a .ts file from a .py file. """

    import argparse

    from PyQt6.QtCore import PYQT_VERSION_STR

    from .user import UserException

    # The program name.
    PROGRAM_NAME = 'pylupdate6'

    # Parse the command line.
    parser = argparse.ArgumentParser(prog=PROGRAM_NAME,
            description="Python Language Update Tool")

    parser.add_argument('-V', '--version', action='version',
            version=PYQT_VERSION_STR)
    parser.add_argument('--exclude', action='append', metavar="PATTERN",
            help="exclude matching files when reading a directory")
    parser.add_argument('--no-obsolete', '-no-obsolete', action='store_true',
            help="remove any obsolete translated messages")
    parser.add_argument('--no-summary', action='store_true',
            help="suppress the summary")
    parser.add_argument('--ts', '-ts', action='append', metavar="FILE",
            required=True,
            help="a .ts file to update or create")
    parser.add_argument('--verbose', action='store_true',
            help="show progress messages")
    parser.add_argument('file', nargs='+',
            help="the .py or .ui file, or directory to be read")

    args = parser.parse_args()

	# Update the translation files.
    try:
        lupdate(args.file, args.ts, args.no_obsolete, args.no_summary,
                args.verbose, args.exclude)
    except UserException as e:
        print("{0}: {1}".format(PROGRAM_NAME, e), file=sys.stderr)
        return 1
    except:
        if args.verbose:
            import traceback

            traceback.print_exception(*sys.exc_info())
        else:
            print("""An unexpected error occurred.
Check that you are using the latest version of {name} and send an error
report to the PyQt mailing list and include the following information:

- the version of {name} ({version})
- the .py or .ui file that caused the error (as an attachment)
- the verbose output of {name} (use the --verbose flag when calling
  {name})""".format(name=PROGRAM_NAME, version=PYQT_VERSION_STR),
                    file=sys.stderr)

        return 2

    return 0


if __name__ == '__main__':
    sys.exit(main())
