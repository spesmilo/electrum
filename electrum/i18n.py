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
import json
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
            _logger.warning(
                f"rejected translation string: failed to parse. original={msg!r}. {translation=!r}",
                only_once=True)
            return msg
        # num of replacement fields must match:
        if len(parsed1) != len(parsed2):
            _logger.warning(
                f"rejected translation string: num replacement fields mismatch. original={msg!r}. {translation=!r}",
                only_once=True)
            return msg
        # set of "field_name"s must not change. (re-ordering is explicitly allowed):
        field_names1 = set(tupl[1] for tupl in parsed1)
        field_names2 = set(tupl[1] for tupl in parsed2)
        if field_names1 != field_names2:
            _logger.warning(
                f"rejected translation string: set of field_names mismatch. original={msg!r}. {translation=!r}",
                only_once=True)
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


# note: The values (human-visible lang names) should be either in English or in their own lang,
#       but NOT translated to the currently selected lang.
#       e.g. "fr_FR" we could show as either "French" or "Francais", or even as "French - Francais",
#       but it is evil to show it as "Franzosisch". How am I supposed to switch back to English from Korean??? :)
languages = {
    '': _('Default'),
    'ar_SA': 'Arabic',
    'bg_BG': 'Bulgarian',
    'cs_CZ': 'Czech',
    'da_DK': 'Danish',
    'de_DE': 'German',
    'el_GR': 'Greek',
    'eo_UY': 'Esperanto',
    'en_UK': 'English',  # selecting this guarantees seeing the untranslated source strings
    'es_ES': 'Spanish',
    'fa_IR': 'Persian',
    'fr_FR': 'French',
    'hu_HU': 'Hungarian',
    'hy_AM': 'Armenian',
    'id_ID': 'Indonesian',
    'it_IT': 'Italian',
    'ja_JP': 'Japanese',
    'ky_KG': 'Kyrgyz',
    'lv_LV': 'Latvian',
    'nb_NO': 'Norwegian Bokmal',
    'nl_NL': 'Dutch',
    'pl_PL': 'Polish',
    'pt_BR': 'Portuguese (Brazil)',
    'pt_PT': 'Portuguese',
    'ro_RO': 'Romanian',
    'ru_RU': 'Russian',
    'sk_SK': 'Slovak',
    'sl_SI': 'Slovenian',
    'sv_SE': 'Swedish',
    'ta_IN': 'Tamil',
    'th_TH': 'Thai',
    'tr_TR': 'Turkish',
    'uk_UA': 'Ukrainian',
    'vi_VN': 'Vietnamese',
    'zh_CN': 'Chinese Simplified',
    'zh_TW': 'Chinese Traditional',
}
assert '' in languages


def get_gui_lang_names(*, show_completion_percent: bool = True) -> dict[str, str]:
    """Returns a  lang_code -> lang_name  mapping, sorted.

    If show_completion_percent is True, lang_name includes a % estimate for translation completeness.
    """
    # calc catalog sizes
    if show_completion_percent:
        stats = _get_stats()
    # sort ("Default" first, then "English", then lexicographically sorted names)
    languages_copy = languages.copy()
    lang_pair_default = ("", languages_copy.pop("")) # pop "Default"
    lang_pair_english = ("en_UK", languages_copy.pop("en_UK")) # pop "English"
    lang_pairs_sorted = sorted(languages_copy.items(), key=lambda x: x[1])
    # fancy names
    gui_lang_names = {}  # type: dict[str, str]
    gui_lang_names[lang_pair_default[0]] = lang_pair_default[1]
    gui_lang_names[lang_pair_english[0]] = lang_pair_english[1]
    for lang_code, lang_name in lang_pairs_sorted:
        if show_completion_percent and stats:
            source_str_cnt = max(stats["source_string_count"], 1)  # avoid div-by-zero
            try:
                lang_data = stats["translations"][lang_code]
            except KeyError as e:
                _logger.warning(f"missing language from stats.json: {e!r}")
                catalog_percent = "??"
            else:
                translated_str_cnt = lang_data["string_count"]
                catalog_percent = round(100 * translated_str_cnt / source_str_cnt)
            gui_lang_names[lang_code] = f"{lang_name} ({catalog_percent}%)"
        else:
            gui_lang_names[lang_code] = lang_name
    return gui_lang_names


_stats = None
def _get_stats() -> dict:
    global _stats
    if _stats is None:
        fname = f"{LOCALE_DIR}/stats.json"
        try:
            with open(fname, "r", encoding="utf-8") as f:
                text = f.read()
        except OSError as e:  # we tolerate the file missing
            # This can happen e.g. when running from git clone if user did not run build_locale.sh.
            _logger.info(f"failed to open stats file {fname!r} - built locale (translations) missing??: {e!r}")
            _stats = {}
        else:  # found file. if it is there, it MUST parse correctly
            _stats = json.loads(text)
    return _stats
