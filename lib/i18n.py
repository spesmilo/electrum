#!/usr/bin/env python
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

if os.path.exists('./locale'):
    LOCALE_DIR = './locale'
else:
    LOCALE_DIR = '/usr/share/locale'

language = gettext.translation('electrum', LOCALE_DIR, fallback = True)

def _(x):
    global language
    return language.ugettext(x)

def set_language(x):
    global language
    if x: language = gettext.translation('electrum', LOCALE_DIR, fallback = True, languages=[x])
    
    
languages = {
    '':_('Default'),
    'br':_('Brasilian'),
    'cs':_('Czech'),
    'de':_('German'),
    'eo':_('Esperanto'),
    'en':_('English'),
    'es':_('Spanish'),
    'fr':_('French'),
    'it':_('Italian'),
    'lv':_('Latvian'),
    'nl':_('Dutch'),
    'ru':_('Russian'),
    'sl':_('Slovenian'),
    'vi':_('Vietnamese'),
    'zh':_('Chinese')
    }
