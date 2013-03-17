

class BasePlugin:

    def get_info(self):
        return self.fullname, self.description

    def __init__(self, gui, name, fullname, description):
        self.name = name
        self.fullname = fullname
        self.description = description
        self.gui = gui
        self.config = gui.config
        self.requires_settings = False

    def toggle(self):
        enabled = not self.is_enabled()
        self.set_enabled(enabled)
        self.init_gui()
        return enabled
    
    def init_gui(self):
        pass

    def is_enabled(self):
        return self.is_available() and self.config.get('use_'+self.name) is True

    def is_available(self):
        return True

    def set_enabled(self, enabled):
        self.config.set_key('use_'+self.name, enabled, True)

    def settings_dialog(self):
        pass
