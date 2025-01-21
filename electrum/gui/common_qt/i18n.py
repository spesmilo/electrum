from PyQt6.QtCore import QTranslator

from electrum.i18n import _


class ElectrumTranslator(QTranslator):
    """Delegator for Qt translations to gettext"""
    def __init__(self, parent=None):
        super().__init__(parent)

        # explicit enumeration of translatable strings from Qt standard library, so these
        # will be included in the electrum gettext translation template
        self._strings = [_('&Undo'), _('&Redo'), _('Cu&t'), _('&Copy'), _('&Paste'), _('Select All'),
                         _('Copy &Link Location')]

    def translate(self, context, source_text: str, disambiguation, n):
        return _(source_text, context=context)
