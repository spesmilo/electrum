import gettext


class _(str):

    observers = set()
    lang = None

    def __new__(cls, s):
        if _.lang is None:
            _.switch_lang('en')
        t = _.translate(s)
        o = super(_, cls).__new__(cls, t)
        o.source_text = s
        return o

    @staticmethod
    def translate(s, *args, **kwargs):
        return _.lang(s)

    @staticmethod
    def bind(label):
        try:
            _.observers.add(label)
        except:
            pass
        # garbage collection
        new = set()
        for label in _.observers:
            try:
                new.add(label)
            except:
                pass
        _.observers = new

    @staticmethod
    def switch_lang(lang):
        # get the right locales directory, and instantiate a gettext
        from electrum.i18n import LOCALE_DIR, set_language
        locales = gettext.translation('electrum', LOCALE_DIR, languages=[lang], fallback=True)
        _.lang = locales.gettext
        for label in _.observers:
            try:
                label.text = _(label.text.source_text)
            except:
                pass
        # Note that all invocations of _() inside the core electrum library
        # use electrum.i18n instead of electrum.gui.kivy.i18n, so we should update the
        # language there as well:
        set_language(lang)
