import os

from electrum.i18n import _

from PyQt5.QtGui import QFontDatabase

fullname = _('Revealer Backup Utility')
description = ''.join(["<br/>",
    "<b>"+_("Do you have something to hide ?")+"</b>", '<br/>', '<br/>',
    _("This plug-in allows you to create a visually encrypted backup of your wallet seeds, or of custom alphanumeric secrets."), '<br/>'])
available_for = ['qt']

def __init__():
    # Add the two fonts used by Revealer to the database.
    QFontDatabase.addApplicationFont(os.path.join(os.path.dirname(__file__), 'SourceSans3-Bold.otf'))
    QFontDatabase.addApplicationFont(os.path.join(os.path.dirname(__file__), 'DejaVuSansMono-Bold.ttf'))
