#!/usr/bin/env python3
#
# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
#
#
# This generates a 'stats.json' file containing some statistics about translation completeness.

import gettext
import glob
import json
import os

PROJECT_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
LOCALE_DIR = os.path.join(PROJECT_ROOT, "electrum", "locale", "locale")


if __name__ == '__main__':
    catalog_size = {}  # type: dict[str, int]
    source_string_count = None
    # - calc stats
    files_list = glob.glob(f"{LOCALE_DIR}/*/LC_MESSAGES/*.mo")
    for fname in files_list:
        lang_code = os.path.basename(os.path.dirname(os.path.dirname(fname)))
        try:
            t = gettext.translation('electrum', LOCALE_DIR, languages=[lang_code])
        except OSError as e:
            raise Exception(f"cannot find or parse .mo file matching {fname!r}") from e
        # calc catalog size of translated strings
        catalog_size[lang_code] = len(t._catalog)
        # same SourceStringCount header should be present in all .mo files:
        t_info = t.info()
        try:
            ss_cnt = int(t_info["x-electrum-sourcestringcount"])
        except Exception as e:
            raise Exception(
                f"missing or malformed 'x-electrum-sourcestringcount' header, for {lang_code!r}.\n"
                f"found {t_info}"
            ) from e
        if source_string_count is None:
            source_string_count = ss_cnt
        elif source_string_count != ss_cnt:
            raise Exception(
                f"inconsistent 'x-electrum-sourcestringcount' headers! "
                f"prev_cnt={source_string_count}, new_cnt={ss_cnt} (for lang={lang_code})")
    # - convert to json data. example:
    #     {
    #         "source_string_count": 9999,
    #         "translations": {
    #             "de_DE": {
    #                 "string_count": 400,
    #             },
    #             ...
    #         }
    #     }
    json_data = {
        "source_string_count": source_string_count,
        "translations": {},
    }
    for lang_code in catalog_size:
        json_data["translations"][lang_code] = {}
        json_data["translations"][lang_code]["string_count"] = catalog_size[lang_code]
    # - write json to disk
    with open(f"{LOCALE_DIR}/stats.json", "w", encoding="utf-8") as f:
        json_str = json.dumps(
            json_data,
            indent=4,
            sort_keys=True
        )
        f.write(json_str)
    print(f"done. created file '{LOCALE_DIR}/stats.json'")
