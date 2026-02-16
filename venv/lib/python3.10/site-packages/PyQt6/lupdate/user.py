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


class UserException(Exception):
    """ Encapsulate an exception ultimate caused by the user. """

    pass


class User:
    """ A mixin that provides methods for communicating with the user. """

    def __init__(self, verbose, **kwargs):
        """ Initialise the object. """

        super().__init__(**kwargs)

        self._verbose = verbose

    @staticmethod
    def pretty(text):
        """ Returns a pretty-fied version of some text suitable for displaying
        to the user.
        """

        return text.replace('\n', '\\n')

    def progress(self, message):
        """ Display a progress message. """

        if self._verbose:
            print(message)
