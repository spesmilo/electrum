import unittest
from lib.seed_suggestion import SeedSuggestion

class TestSeedSuggestion(unittest.TestCase):

    def test_get_suggestions(self):
        suggestion = SeedSuggestion("../wordlist/english.txt")
        returned_suggestion = suggestion.get_suggestions("z")
        expected_suggestion = ["zebra", "zero", "zone", "zoo"]
        self.assertEqual(expected_suggestion, returned_suggestion)

    def test_get_suggestions_word_length(self):
        suggestion = SeedSuggestion("../wordlist/english.txt")
        suggestion_char_length = 10
        returned_suggestion = suggestion.get_suggestions("z", suggestion_char_length)
        expected_suggestion = ["zebra", "zero", "..."]
        self.assertEqual(expected_suggestion, returned_suggestion)

    def test_get_wordlist(self):
        suggestion = SeedSuggestion("../wordlist/english.txt")
        with open("../wordlist/english.txt") as wordlist:
            expected_words = [x.strip() for x in wordlist.readlines()]
        actual_words = suggestion.get_wordlist()
        self.assertListEqual(expected_words, actual_words)

    def test_get_suggestions_space(self):
        suggestion = SeedSuggestion("../wordlist/english.txt")
        returned_suggestion = suggestion.get_suggestions(" ")
        self.assertListEqual(["[none]"], returned_suggestion)