from electrum import i18n
from electrum.i18n import _ensure_translation_keeps_format_string_syntax_similar

from . import ElectrumTestCase


syntax_check_decorator = _ensure_translation_keeps_format_string_syntax_similar


class TestSyntaxChecks(ElectrumTestCase):
    # convention: source strings are lowercase, dest strings are uppercase

    def test_no_format(self):
        src, dst = ("hello there", "HELLO THEEEEERE")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_malformed_src_string_raises(self):
        src, dst = ("hel{lo there", "HELLO THE{}RE")
        with self.assertRaises(ValueError):
            syntax_check_decorator(lambda x: dst)(src)

    def test_malformed_dst_string_gets_rejected(self):
        src, dst = ("hel{}lo there", "HELLO THE{RE")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there", "HELLO THE{RE")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there", "HELLO THE{{}RE")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))

    def test_simple_substitution(self):
        src, dst = ("hel{}lo there", "HELLO THE{}RE")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{}lo {} there {}", "HELLO {} THE{}RE {}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_positional_substitution(self):
        src, dst = ("hel{0}lo there", "HELLO THE{0}RE")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{0}lo there {1}", "HELLO THE{0}RE {1}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{0}lo {2} there {1}", "HELLO THE{0}RE {2} {1}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_keyword_substitution(self):
        src, dst = ("hello there {title}. {name}. welc", "HELLO THERE {title}. {name}. WELC")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_mixed_sub(self):
        src, dst = ("{1} aaa {qq} {0} bbb", "{1} AAA {qq} {0} BBB")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("{1} aaa {pp} {qq} {0} bbb", "{1} AAA {pp} {qq} {0} BBB")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_allow_reordering_replacement_fields(self):  # language-flexibility
        src, dst = ("time left: {0} minutes, {1} seconds", "TIME LEFT: {1} SECONDS, {0} MINUTES")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("{1} aaa {pp} {qq} {0} bbb", "{qq} AAA {0} {1} {pp} BBB")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_replacement_field_name_cannot_change(self):
        # rejects:
        src, dst = ("hel{}lo there", "HELLO THE{RE}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{}lo there", "HELLO THE{0}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{0}lo there", "HELLO THE{}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{0}lo there", "HELLO THE{RE}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{RE}lo there", "HELLO THE{}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hel{RE}lo there", "HELLO THE{0}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        # we only check the set of field_names is invariant, so this is allowed:
        src, dst = ("hello there {} {} {} {p} {q}", "HELLO THERE {} {q} {q} {p} {q}")
        self.assertEqual(dst, syntax_check_decorator(lambda x: dst)(src))

    def test_replacement_field_count_cannot_change(self):
        # rejects:
        src, dst = ("hello there", "HELLO THERE {}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there", "HELLO {} {} THERE")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello {} there", "HELLO THERE {} {}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there {}", "HELLO THERE")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there {p} {q} {r}", "HELLO THERE {p} {q}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there {p} {q} {r}", "HELLO THERE {p} {q} {r} {s}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
        src, dst = ("hello there {p} {0}", "HELLO THERE {p}")
        self.assertEqual(src, syntax_check_decorator(lambda x: dst)(src))
