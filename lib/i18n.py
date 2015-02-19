#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import gettext, os

LOCALE_DIR = os.path.join(os.path.dirname(__file__), 'locale')
language = gettext.translation('electrum', LOCALE_DIR, fallback = True)


def _(x):
    global language
    dic = [('Bitcoin', 'Litecoin'), ('bitcoin', 'litecoin'), (u'比特币', u'莱特币')]
    for b, l in dic:
        x = x.replace(l, b)
    t = language.ugettext(x)
    for b, l in dic:
        t = t.replace(b, l)
    return t

def set_language(x):
    global language
    if x: language = gettext.translation('electrum', LOCALE_DIR, fallback = True, languages=[x])


languages = {
    '':_('Default'),
    'pt_PT':_('Portuguese'),
    'pt_BR':_('Brasilian'),
    'cs_CZ':_('Czech'),
    'de_DE':_('German'),
    'eo_UY':_('Esperanto'),
    'en_UK':_('English'),
    'es_ES':_('Spanish'),
    'fr_FR':_('French'),
    'it_IT':_('Italian'),
    'ja_JP':_('Japanese'),
    'lv_LV':_('Latvian'),
    'nl_NL':_('Dutch'),
    'ru_RU':_('Russian'),
    'sl_SI':_('Slovenian'),
    'ta_IN':_('Tamil'),
    'vi_VN':_('Vietnamese'),
    'zh_CN':_('Chinese')
    }
