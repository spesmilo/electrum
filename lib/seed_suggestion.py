# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
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

class SeedSuggestion(object):
    __words = []

    def __init__(self, wordlist_file):
        with open(wordlist_file) as wordlist_file:
            self.__words = [w.strip() for w in wordlist_file.readlines()]

    def get_suggestions(self, prefix, max_characters=float("inf")):
        if prefix == "": return []
        suggestions = []
        for w in range(0, len(self.__words)):
            if self.__words[w].startswith(prefix):
                if len(''.join(suggestions)) + \
                        len(self.__words[w]) < max_characters:
                    suggestions.append(self.__words[w])
                else:
                    suggestions.append("...")
                    break
        return suggestions if len(suggestions) > 0 else ["[none]"]

    def get_wordlist(self):
        return list(self.__words)