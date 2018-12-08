#!/usr/bin/env python3
#
# Generates strings.xml files from the gettext files. This script is run automatically by the
# Gradle task `generateStrings`.
#
# This script has no special requirements, but it runs contrib/make_locale, which requires
# the Python package `requests`, and the OS package `gettext`.

import argparse
from collections import Counter, defaultdict
from datetime import datetime
import gettext
import os
from os.path import abspath, basename, dirname, isdir, join
import re
from subprocess import run
import sys


SCRIPT_NAME = basename(__file__)
EC_ROOT = abspath(join(dirname(__file__), "../.."))

JAVA_KEYWORDS = set([
    "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class",
    "const", "continue", "default", "do", "double ", "else", "enum", "extends", "final",
    "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int",
    "interface ", "long", "native", "new", "package", "private", "protected", "public",
    "return", "short", "static", "strictfp", "super", "switch ", "synchronized", "this",
    "throw", "throws", "transient", "try", "void", "volatile", "while"])

KOTLIN_KEYWORDS = set([  # "Hard" keywords only.
    "as", "break", "class", "continue", "do", "else", "false", "for", "fun", "if", "in",
    "interface", "is", "null", "object", "package", "return", "super", "this", "throw",
    "true", "try", "typealias", "typeof" "val", "var", "when", "while"])

KEYWORDS = JAVA_KEYWORDS | KOTLIN_KEYWORDS


def main():
    args = parse_args()
    if not args.no_download:
        log("Running make_locale")
        run([sys.executable, join(EC_ROOT, "contrib/make_locale")], check=True)

    locale_dir = join(EC_ROOT, "lib/locale")
    src_strings = set()
    lang_strings = defaultdict(list)
    for lang_region in [name for name in os.listdir(locale_dir)
                        if isdir(join(locale_dir, name))]:
        lang, region = lang_region.split("_")
        trans = gettext.translation("electron-cash", locale_dir, [lang_region])
        catalog = {src_str: tgt_str for src_str, tgt_str in trans._catalog.items()
                   if not is_excluded(src_str)}
        lang_strings[lang].append((region, catalog))
        src_strings.update(catalog)

    ids = make_ids(src_strings)

    # The region with the most translations is output without a country code so it will act as
    # a fallback for the others.
    #
    # This doesn't entirely work for Chinese. Apparently Android 7 and later treats traditional
    # and simplified Chinese as unrelated languages. Since it interprets "zh" as being
    # simplified, it will never use it in any traditional locale, preferring English instead
    # (https://gist.github.com/amake/0ac7724681ac1c178c6f95a5b09f03ce).
    for lang, region_strings in lang_strings.items():
        region_strings.sort(key=region_order, reverse=True)
        for i, (region, strings) in enumerate(region_strings):
            write_xml(lang if i == 0 else "{}-r{}".format(lang, region),
                      strings, ids)

    # The main strings.xml should be generated last, because this script will only be
    # automatically run if it's missing.
    write_xml("", {s: s for s in src_strings}, ids)


def region_order(item):
    region, strings = item
    return (region == "CN",   # "zh" must always be simplified Chinese: see comment above.
            len(strings))


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-download", action="store_true")
    return ap.parse_args()


def is_excluded(src_str):
    return (re.search(r"^\W*$", src_str) or         # Empty or only punctuation.
            src_str in ["Auto connect"])            # Clashes with "Auto-connect".


# Returns a dict {s: id} where each `s` is a string in `strings`, and `id` is a unique
# Java/Kotlin identifier generated from it.
def make_ids(strings):
    ids_out = {}
    for id_options in [dict(lower=True, squash=True),
                       dict(lower=True, squash=False),
                       dict(lower=False, squash=False)]:
        ids_in = {s: tuple(str_to_id(s, **id_options).split("_"))
                  for s in strings}
        try:
            make_ids_inner(ids_in, ids_out)
            return {s: "_".join(id) for s, id in ids_out.items()}
        except DuplicateStringError:
            strings = list(ids_in)

    # The remaining strings differ only in equal-length sequences of space or punctuation. We
    # could handle this by generating unique suffixes for the ID, but that could cause the ID
    # to get a different value when the string set changes. So it's safer to just list the
    # undesired string in is_excluded.
    raise Exception("Failed to make unique IDs for the following strings:\n" +
                    "\n".join(repr(s) for s in sorted(strings, key=case_insensitive)))


def make_ids_inner(ids_in, ids_out):
    max_words = 2
    existing_ids = list(ids_out.values())
    prev_counts = None
    while ids_in:
        counts = Counter(existing_ids)
        counts.update([id[:max_words] for id in ids_in.values()])
        if counts == prev_counts:
            raise DuplicateStringError()

        strings_done = []
        for s, id in ids_in.items():
            short_id = id[:max_words]
            if counts[short_id] == 1:
                ids_out[s] = short_id
                strings_done.append(s)
        for s in strings_done:
            del ids_in[s]

        prev_counts = counts
        max_words += 1


class DuplicateStringError(Exception):
    pass


# Returns an identifier generated from every word in the given string.
def str_to_id(s, *, lower, squash):
    if not isinstance(s, str):
        # For plural forms (which Electron Cash currently doesn't use), gettext returns a (str,
        # int) tuple.
        raise TypeError("{!r} is not a string".format(s))

    if lower:
        s = s.lower()
    if squash:
        pattern = r"\W+"
        lstrip = "0123456789_"
        rstrip = "_"
    else:
        pattern = r"\W"
        lstrip = "0123456789"
        rstrip = ""
    id = (re.sub(pattern, "_", s.replace("'", ""),  # Combine contractions.
                 flags=re.ASCII)
          .lstrip(lstrip)
          .rstrip(rstrip))
    if id in KEYWORDS:
        id += "_"
    return id


def write_xml(res_suffix, strings, ids):
    dir_name = "values" + ("-" + res_suffix if res_suffix else "")
    base_name = "strings.xml"
    log("Generating {}/{}".format(dir_name, base_name))

    abs_dir_name = join(EC_ROOT, "android/app/src/main/res", dir_name)
    os.makedirs(abs_dir_name, exist_ok=True)

    timestamp = datetime.utcnow().isoformat()
    with open(join(abs_dir_name, base_name), "w", encoding="UTF-8") as f:
        print('<?xml version="1.0" encoding="utf-8"?>', file=f)
        print('<!-- Generated by {} at {} -->'.format(SCRIPT_NAME, timestamp), file=f)
        print('<!-- DO NOT EDIT: edit the source Python files instead. -->', file=f)
        print('<resources>', file=f)
        for id, s in sorted(((ids[src_str], str_for_xml(tgt_str))
                             for src_str, tgt_str in strings.items()),
                            key=lambda x: case_insensitive(x[0])):
            print('    <string name="{}">{}</string>'.format(id, s), file=f)
        print('</resources>', file=f)


XML_REPLACEMENTS = [
    # Generic XML syntax
    ("&", "&amp;"),
    ("<", "&lt;"),
    (">", "&gt;"),

    # Android-specific syntax
    # (https://developer.android.com/guide/topics/resources/string-resource#escaping_quotes)
    (re.compile(r"^([@?])"), r"\1"),
    ("'", r"\'"),
    ('"', r'\"'),
    ("\n", r"\n"),

    # Replace Python str.format syntax with Java String.format syntax.
    ("{}", "%s"),
]

def str_for_xml(s):
    for old, new in XML_REPLACEMENTS:
        if isinstance(old, str):
            s = s.replace(old, new)
        else:
            s = re.sub(old, new, s)
    return s


def log(s):
    print(s)
    sys.stdout.flush()


def case_insensitive(s):
    return (s.lower(), s)


if __name__ == "__main__":
    main()
