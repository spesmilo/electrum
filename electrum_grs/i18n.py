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
from typing import Optional

import gettext

from .logging import get_logger


_logger = get_logger(__name__)
LOCALE_DIR = os.path.join(os.path.dirname(__file__), 'locale')

# Set initial default language to None. i.e. translations explicitly disabled.
# The main script or GUIs can call set_language to enable translations.
language = gettext.translation('electrum', fallback=True, class_=gettext.NullTranslations)


# note: do not use old-style (%) formatting inside translations,
#       as syntactically incorrectly translated strings would raise exceptions (see #3237).
#       e.g. consider  _("Connected to %d nodes.") % n
#                      >>> "Connecté aux noeuds" % n
#                      TypeError: not all arguments converted during string formatting
# note: f-strings cannot be translated! see https://stackoverflow.com/q/49797658
#       So this does not work:   _(f"My name: {name}")
#       instead use .format:     _("My name: {}").format(name)
def _(msg: str, *, context=None) -> str:
    if msg == "":
        return ""  # empty string must not be translated. see #7158
    global language
    if context:
        contexts = [context]
        if context[-1] != "|":  # try with both "|" suffix and without
            contexts.append(context + "|")
        else:
            contexts.append(context[:-1])
        for ctx in contexts:
            dic = [('BTC', 'GRS'), ('Electrum Technologies GmbH', 'Groestlcoin Developers'), ('Electrum', 'Electrum-GRS'), ('Bitcoin', 'Groestlcoin'), ('Bitcoins', 'Groestlcoins'), ('bitcoin', 'groestlcoin'), ('bitcoins', 'groestlcoins'), ('satoshi', 'gro'), ('satoshis', 'gros'), ('غرسلكوين' ,'بتكوين'), ('غرسلكوين' ,'بيتكوين'), ('غرسلكوين' ,'بیت‌کوین'), ('גרוסטלקוין' ,'הביטקוין'), ('비트코인', '그로스톨코인'), ('比特币', '格羅斯币'), ('比特幣', '格羅斯幣'), ('Биткоин', 'Грoстлкоин'), ('Биткойн', 'Грoстлкоин'), ('биткойн', 'Грoстлкоин'), ('ビットコイン', 'グロストルコイン')]
            for b, m in dic:
                msg = msg.replace(m, b)
            t = language.pgettext(ctx, msg)
            for b, m in dic:
                t = t.replace(b, m)
            if t != msg:  # found non-trivial translation
                return t
        # else try without context
    dic = [('BTC', 'GRS'), ('Electrum Technologies GmbH', 'Groestlcoin Developers'), ('Electrum', 'Electrum-GRS'), ('Bitcoin', 'Groestlcoin'), ('Bitcoins', 'Groestlcoins'), ('bitcoin', 'groestlcoin'), ('bitcoins', 'groestlcoins'), ('satoshi', 'gro'), ('satoshis', 'gros'), ('غرسلكوين' ,'بتكوين'), ('غرسلكوين' ,'بيتكوين'), ('غرسلكوين' ,'بیت‌کوین'), ('גרוסטלקוין' ,'הביטקוין'), ('비트코인', '그로스톨코인'), ('比特币', '格羅斯币'), ('比特幣', '格羅斯幣'), ('Биткоин', 'Грoстлкоин'), ('Биткойн', 'Грoстлкоин'), ('биткойн', 'Грoстлкоин'), ('ビットコイン', 'グロストルコイン')]
    for b, m in dic:
        msg = msg.replace(m, b)
    t = language.gettext(msg)
    for b, m in dic:
        t = t.replace(b, m)
    return t


def set_language(x: Optional[str]) -> None:
    _logger.info(f"setting language to {x!r}")
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
    'pt_BR': _('Portuguese (Brazil)'),
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
assert '' in languages
