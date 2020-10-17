# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2019 Axel Gembe <derago@gmail.com>
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


def char_to_monospace(char: str) -> str:
    if char >= 'A' and char <= 'Z':
        return chr(ord(char) - ord('A') + 0x1d670)
    elif char >= 'a' and char <= 'z':
        return chr(ord(char) - ord('a') + 0x1d68a)
    elif char >= '0' and char <= '9':
        return chr(ord(char) - ord('0') + 0x1d7f6)
    return char


def str_to_monospace(text: str) -> str:
    return ''.join(char_to_monospace(c) for c in text)


def char_to_fullwidth(char: str) -> str:
    if char >= '!' and char <= '~':
        return chr(ord(char) - ord('!') + 0xff01)
    elif char == ' ':
        return chr(0x2003)  # em space
    return char


def str_to_fullwidth(text: str) -> str:
    return ''.join(char_to_monospace(c) for c in text)
