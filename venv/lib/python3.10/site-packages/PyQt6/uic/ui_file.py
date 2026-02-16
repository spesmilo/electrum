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


from xml.etree import ElementTree


class UIFile:
    """ Encapsulate a Designer .ui file. """

    def __init__(self, ui_file):
        """ Initialise the .ui file. """

        # Get the name of the .ui file allowing it to be a file object.
        if hasattr(ui_file, 'read'):
            self._ui_file = getattr(ui_file, 'name', "unknown")
        else:
            self._ui_file = ui_file

        try:
            document = ElementTree.parse(ui_file)
        except Exception as e:
            self._raise_exception("invalid Qt Designer file", detail=str(e))

        # Perform some sanity checks.
        root = document.getroot()

        if root.tag != 'ui':
            self._raise_exception("not created by Qt Designer")

        version = root.get('version')
        if version is None:
            self._raise_exception("missing version number")

        if version != '4.0':
            self._raise_exception("only Qt Designer files v4.0 are supported")

        # Extract the top-level elements.
        self.button_groups = None
        self.connections = None
        self.custom_widgets = None
        self.layout_default = None
        self.tab_stops = None
        self.widget = None

        self.class_name = None

        for el in root:
            if el.tag == 'class':
                self.class_name = el.text
            elif el.tag == 'buttongroups':
                self.button_groups = el
            elif el.tag == 'connections':
                self.connections = el
            elif el.tag == 'customwidgets':
                self.custom_widgets = el
            elif el.tag == 'layoutdefault':
                self.layout_default = el
            elif el.tag == 'tabstops':
                self.tab_stops = el
            elif el.tag == 'widget':
                self.widget = el

        # The <class> element was optional in legacy versions of the schema.
        if not self.class_name:
            if self.widget is not None:
                self.class_name = self.widget.get('name')

            if not self.class_name:
                self._raise_exception(
                        "unable to determine the name of the UI class")

    def _raise_exception(self, message, detail=''):
        """ Raise a UIFileException. """

        from .exceptions import UIFileException

        raise UIFileException(self._ui_file, message, detail=detail)
