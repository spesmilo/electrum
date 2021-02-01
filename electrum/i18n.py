#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os

import gettext

LOCALE_DIR = os.path.join(os.path.dirname(__file__), 'locale')
language = gettext.translation('electrum', LOCALE_DIR, fallback=True)


# note: f-strings cannot be translated! see https://stackoverflow.com/q/49797658
#       So this does not work:   _(f"My name: {name}")
#       instead use .format:     _("My name: {}").format(name)
def _(x):
    global language
    return language.gettext(x)


def set_language(x):
    # todo remove it when all translations will be available
    x = 'en_UK'
    global language
    if x:
        language = gettext.translation('electrum', LOCALE_DIR, fallback=True, languages=[x])


languages = {
    '': _('Default'),
    'en_UK': _('English'),
    # todo uncomment supported languages
#    'ar_SA': _('Arabic'),
#    'de_DE': _('German'),
#    'es_ES': _('Spanish'),
#    'ja_JP': _('Japanese'),
#    'ko_KR': _('Korean'),
#    'pt_PT': _('Portuguese'),
#    'tr_TR': _('Turkish'),
#    'vi_VN': _('Vietnamese'),
#    'zh_CN': _('Chinese Simplified'),

}
