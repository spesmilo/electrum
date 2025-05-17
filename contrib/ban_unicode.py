#!/usr/bin/env python3
#
# Copyright (C) 2025 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
#
# This script scans the whole codebase for unicode characters and
# errors if it finds any, unless the character is specifically whitelisted below.
# The motivation is to protect against homoglyph attacks, invisible unicode characters,
# bidirectional and other control characters, and other malicious unicode usage.
# Given that we mostly expect to use ASCII characters in the source code,
# the most robust and generic fix seems to be to just ban all unicode usage.

import os.path
import subprocess
import sys

project_root = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
os.chdir(project_root)

EXCLUDE_PATH_PREFIX = {
    "electrum/wordlist/",
    "fastlane/",
    "tests/",
}
EXCLUDE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".ttf", ".otf", ".pdn", ".icns", ".ico", ".gif",
}
UNICODE_WHITELIST = {
    "💬", "🗯", "⚠", chr(0xfe0f), "✓", "▷", "▽", "…", "•", "█", "™", "≈",
    "á", "é", "’",
    "│", "─", "└", "├",
}

exit_code = 0

bfiles = subprocess.check_output(["git", "ls-files"])
bfiles = bfiles.decode("utf-8")
for file_path in bfiles.splitlines():
    if os.path.isdir(file_path):
        continue
    if any(file_path.startswith(pattern) for pattern in EXCLUDE_PATH_PREFIX):
        continue
    _fname, ext = os.path.splitext(file_path)
    if ext in EXCLUDE_EXTENSIONS:
        continue
    # open file
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f.read().splitlines()):
                for char in line:
                    if ord(char)>0x7f and char not in UNICODE_WHITELIST:
                        print(f"{file_path}:{line_no}. {line=}. hex={hex(ord(char))}. {char=}")
                        exit_code = 1
    except UnicodeDecodeError as e:
        raise Exception(f"cannot parse file {file_path=}") from e

sys.exit(exit_code)
