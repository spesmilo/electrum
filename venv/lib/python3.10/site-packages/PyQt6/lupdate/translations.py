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


class Context:
    """ Encapsulate a message context. """

    def __init__(self, name):
        """ Initialise the context. """

        self.name = name
        self.messages = []


class EmbeddedComments:
    """ Encapsulate information for a translator embedded in comments. """

    def __init__(self):
        """ Initialise the object. """

        self.message_id = ''
        self.extra_comments = []
        self.extras = []


class Message:
    """ Encapsulate a message. """

    def __init__(self, filename, line_nr, source, comment, numerus):
        """ Initialise the message. """

        self.filename = filename
        self.line_nr = line_nr
        self.source = source
        self.comment = comment
        self.numerus = numerus
        self.embedded_comments = EmbeddedComments()
