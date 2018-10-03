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


def _(x):
    global language
    return language.gettext(x)


def set_language(x):
    global language
    if x:
        language = gettext.translation('electrum', LOCALE_DIR, fallback=True, languages=[x])


languages = {
    '': _('Default'),
    'ar_SA': _('Arabic'),
    'bg_BG': _('Bulgarian'),
    'cs_CZ': _('Czech'),
    'da_DK': _('Danish'),
    'de_DE': _('German'),
    'el_GR': _('Greek'),
    'eo_UY': _('Esperanto'),
    'en_UK': _('English'),
    'es_ES': _('Spanish'),
    'fa_IR': _('Persian'),
    'fr_FR': _('French'),
    'hu_HU': _('Hungarian'),
    'hy_AM': _('Armenian'),
    'id_ID': _('Indonesian'),
    'it_IT': _('Italian'),
    'ja_JP': _('Japanese'),
    'ky_KG': _('Kyrgyz'),
    'lv_LV': _('Latvian'),
    'nb_NO': _('Norwegian Bokmal'),
    'nl_NL': _('Dutch'),
    'pl_PL': _('Polish'),
    'pt_BR': _('Brasilian'),
    'pt_PT': _('Portuguese'),
    'ro_RO': _('Romanian'),
    'ru_RU': _('Russian'),
    'sk_SK': _('Slovak'),
    'sl_SI': _('Slovenian'),
    'sv_SE': _('Swedish'),
    'ta_IN': _('Tamil'),
    'th_TH': _('Thai'),
    'tr_TR': _('Turkish'),
    'uk_UA': _('Ukrainian'),
    'vi_VN': _('Vietnamese'),
    'zh_CN': _('Chinese Simplified'),
    'zh_TW': _('Chinese Traditional')
}
