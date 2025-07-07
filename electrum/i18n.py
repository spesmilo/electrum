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
import functools
import os
import string
from typing import Optional

import gettext

from .logging import get_logger


_logger = get_logger(__name__)
LOCALE_DIR = os.path.join(os.path.dirname(__file__), 'locale', 'locale')


def _get_null_translations():
    """Returns a gettext Translations obj with translations explicitly disabled."""
    return gettext.translation('electrum', fallback=True, class_=gettext.NullTranslations)


# Set initial default language to None. i.e. translations explicitly disabled.
# The main script or GUIs can call set_language to enable translations.
_language = _get_null_translations()


def _ensure_translation_keeps_format_string_syntax_similar(translator):
    """This checks that the source string is syntactically similar to the translated string.
    If not, translations are rejected by falling back to the source string.
    """
    sf = string.Formatter()
    @functools.wraps(translator)
    def safe_translator(msg: str, **kwargs):
        translation = translator(msg, **kwargs)
        parsed1 = list(sf.parse(msg))  # iterable of tuples (literal_text, field_name, format_spec, conversion)
        try:
            parsed2 = list(sf.parse(translation))
        except ValueError:  # malformed format string in translation
            _logger.info(f"rejected translation string: failed to parse. original={msg!r}. {translation=!r}")
            return msg
        # num of replacement fields must match:
        if len(parsed1) != len(parsed2):
            _logger.info(f"rejected translation string: num replacement fields mismatch. original={msg!r}. {translation=!r}")
            return msg
        # set of "field_name"s must not change. (re-ordering is explicitly allowed):
        field_names1 = set(tupl[1] for tupl in parsed1)
        field_names2 = set(tupl[1] for tupl in parsed2)
        if field_names1 != field_names2:
            _logger.info(f"rejected translation string: set of field_names mismatch. original={msg!r}. {translation=!r}")
            return msg
        # checks done.
        return translation
    return safe_translator


# note: do not use old-style (%) formatting inside translations,
#       as syntactically incorrectly translated strings often raise exceptions (see #3237).
#       e.g. consider  _("Connected to %d nodes.") % n            # <- raises. do NOT use
#                      >>> "Connecté aux noeuds" % n
#                      TypeError: not all arguments converted during string formatting
# note: f-strings cannot be translated! see https://stackoverflow.com/q/49797658
#       So this does NOT work:   _(f"My name: {name}")            # <- cannot be translated. do NOT use
#       instead use .format:     _("My name: {}").format(name)    # <- works. prefer this way.
# note: positional and keyword-based substitution also works with str.format().
#       These give more flexibility to translators: it allows reordering the substituted values.
#       However, only if the translators understand and use it correctly!
#          _("time left: {0} minutes, {1} seconds").format(t//60, t%60)                   # <- works. ok to use
#          _("time left: {mins} minutes, {secs} seconds").format(mins=t//60, secs=t%60)   # <- works, but too complex
@_ensure_translation_keeps_format_string_syntax_similar
def _(msg: str, *, context=None) -> str:
    if msg == "":
        return ""  # empty string must not be translated. see #7158
    if context:
        contexts = [context]
        if context[-1] != "|":  # try with both "|" suffix and without
            contexts.append(context + "|")
        else:
            contexts.append(context[:-1])
        for ctx in contexts:
            out = _language.pgettext(ctx, msg)
            if out != msg:  # found non-trivial translation
                return out
        # else try without context
    return _language.gettext(msg)


def set_language(x: Optional[str]) -> None:
    _logger.info(f"setting language to {x!r}")
    global _language
    if not x:
        return
    if x.startswith("en_"):
        # Setting the language to "English" is a protected special-case:
        # we disable all translations and use the source strings.
        _language = _get_null_translations()
    else:
        _language = gettext.translation('electrum', LOCALE_DIR, fallback=True, languages=[x])


languages = {
    '': _('Default'),
    'ar_SA': _('Arabic'),
    'bg_BG': _('Bulgarian'),
    'cs_CZ': _('Czech'),
    'da_DK': _('Danish'),
    'de_DE': _('German'),
    'el_GR': _('Greek'),
    'eo_UY': _('Esperanto'),
    'en_UK': _('English'),  # selecting this guarantees seeing the untranslated source strings
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
