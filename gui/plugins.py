

class BasePlugin:

    def __init__(self, gui, name):
        self.gui = gui
        self.name = name
        self.config = gui.config

    def fullname(self):
        return self.name

    def description(self):
        return 'undefined'

    def requires_settings(self):
        return False

    def toggle(self):
        if self.is_enabled():
            if self.disable():
                self.close()
        else:
            if self.enable():
                self.init()

        return self.is_enabled()

    
    def enable(self):
        self.set_enabled(True)
        return True

    def disable(self):
        self.set_enabled(False)
        return True

    def init(self): pass

    def close(self): pass

    def is_enabled(self):
        return self.is_available() and self.config.get('use_'+self.name) is True

    def is_available(self):
        return True

    def set_enabled(self, enabled):
        self.config.set_key('use_'+self.name, enabled, True)

    def settings_dialog(self):
        pass
