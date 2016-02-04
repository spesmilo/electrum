import gettext

class _(str):

    observers = set()
    lang = None

    def __new__(cls, s, *args, **kwargs):
        if _.lang is None:
            _.switch_lang('en')
        t = _.translate(s, *args, **kwargs)
        o = super(_, cls).__new__(cls, t)
        o.source_text = s
        return o

    @staticmethod
    def translate(s, *args, **kwargs):
        return _.lang(s).format(args, kwargs)

    @staticmethod
    def bind(label):
        if isinstance(label.text, _):
            _.observers.add(label)

    @staticmethod
    def switch_lang(lang):
        # get the right locales directory, and instanciate a gettext
        from electrum.i18n import LOCALE_DIR
        locales = gettext.translation('electrum', LOCALE_DIR, languages=[lang], fallback=True)
        _.lang = locales.gettext
        for label in _.observers:
            try:
                label.text = _(label.text.source_text)
            except ReferenceError:
                pass
