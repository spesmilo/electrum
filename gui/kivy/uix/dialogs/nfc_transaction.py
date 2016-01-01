class NFCTransactionDialog(AnimatedPopup):

    mode = OptionProperty('send', options=('send','receive'))

    scanner = ObjectProperty(None)

    def __init__(self, **kwargs):
        # Delayed Init
        global NFCSCanner
        if NFCSCanner is None:
            from electrum_gui.kivy.nfc_scanner import NFCScanner
        self.scanner = NFCSCanner

        super(NFCTransactionDialog, self).__init__(**kwargs)
        self.scanner.nfc_init()
        self.scanner.bind()

    def on_parent(self, instance, value):
        sctr = self.ids.sctr
        if value:
            def _cmp(*l):
                anim = Animation(rotation=2, scale=1, opacity=1)
                anim.start(sctr)
                anim.bind(on_complete=_start)

            def _start(*l):
                anim = Animation(rotation=350, scale=2, opacity=0)
                anim.start(sctr)
                anim.bind(on_complete=_cmp)
            _start()
            return
        Animation.cancel_all(sctr)