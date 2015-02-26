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
    'ar_SA':_('Arabic'),
    'cs_CZ':_('Czech'),
    'da_DK':_('Danish'),
    'de_DE':_('German'),
    'eo_UY':_('Esperanto'),
    'el_GR':_('Greek'),
    'en_UK':_('English'),
    'es_ES':_('Spanish'),
    'fr_FR':_('French'),
    'hu_HU':_('Hungarian'),
    'hy_AM':_('Armenian'),
    'id_ID':_('Indonesian'),
    'it_IT':_('Italian'),
    'ja_JP':_('Japanese'),
    'ky_KG':_('Kyrgyz'),
    'lv_LV':_('Latvian'),
    'nl_NL':_('Dutch'),
    'no_NO':_('Norwegian'),
    'pl_PL':_('Polish'),
    'pt_BR':_('Brasilian'),
    'pt_PT':_('Portuguese'),
    'ro_RO':_('Romanian'),
    'ru_RU':_('Russian'),
    'sk_SK':_('Slovak'),
    'sl_SI':_('Slovenian'),
    'ta_IN':_('Tamil'),
    'th_TH':_('Thai'),
    'vi_VN':_('Vietnamese'),
    'zh_CN':_('Chinese')
    }
