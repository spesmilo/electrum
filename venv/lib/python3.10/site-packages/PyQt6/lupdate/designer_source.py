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


from ..uic import UIFile

from .source_file import SourceFile
from .translations import Context, Message
from .user import User, UserException


class DesignerSource(SourceFile, User):
    """ Encapsulate a Designer source file. """

    def __init__(self, **kwargs):
        """ Initialise the object. """

        super().__init__(**kwargs)

        # Read the source file.
        self.progress("Reading {0}...".format(self.filename))

        try:
            ui_file = UIFile(self.filename)
        except Exception as e:
            raise UserException(str(e))

        if ui_file.widget is not None:
            context = Context(ui_file.class_name)

            # Get each <string> element.  Note that we don't support the
            # <stringlist> element which seems to provide defaults for the
            # attributes of any child <string> elements.
            for string_el in ui_file.widget.iter('string'):
                if string_el.get('notr', 'false') == 'true':
                    continue

                # This can be None or an empty string depending on the exact
                # XML.
                if not string_el.text:
                    continue

                message = Message(self.filename, 0, string_el.text,
                        string_el.get('comment', ''), False)

                extra_comment = string_el.get('extracomment')
                if extra_comment:
                    message.embedded_comments.extra_comments.append(
                            extra_comment)

                context.messages.append(message)

            if context.messages:
                self.contexts.append(context)
