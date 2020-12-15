import json

from electroncash import simple_config


SP_SET_METHODS = {
    bool: "putBoolean",
    float: "putFloat",
    int: "putInt",
    str: "putString",
}

JSON_MARKER = "<json>"

def json_key(key):
    return key + ".json"


# We store the config in the SharedPreferences because it's very easy to base an Android
# settings UI on that. However, we maintain the Python config dict as a cache, because the
# back-end code sometimes calls `get` many times in a loop, and Java method calls are
# relatively slow.
class AndroidConfig(simple_config.SimpleConfig):
    def __init__(self, sp):
        self.sp = sp
        self.spe = self.sp.edit()
        super().__init__(read_user_config_function=self.set_all_from_preferences)

    def set_all_from_preferences(self, _):
        self.user_config = {}
        i = self.sp.getAll().entrySet().iterator()
        while i.hasNext():
            entry = i.next()
            self.set_from_preferences(entry.getKey(), entry.getValue())
        return self.user_config

    # Receives updates from Java code, via the listener in Settings.kt.
    def set_from_preferences(self, key, value):
        if value == JSON_MARKER:
            json_value = self.sp.getString(json_key(key), None)
            if json_value is not None:
                value = json.loads(json_value)
        super()._set_key_in_user_config(key, value, save=False)

    # Receives updates from Python code.
    def _set_key_in_user_config(self, key, value, save=True):
        if value is None:
            self.spe.remove(key)
            self.spe.remove(json_key(key))
        else:
            set_method = SP_SET_METHODS.get(type(value))
            if set_method:
                getattr(self.spe, set_method)(key, value)
            else:
                self.spe.putString(key, JSON_MARKER)
                self.spe.putString(json_key(key), json.dumps(value))

        # If save=False, updates will be held in self.spe until a future call to
        # save_user_config.
        super()._set_key_in_user_config(key, value, save)

    # In case the caller requires a synchronous write, we'll use `commit` rather than `apply`.
    def save_user_config(self):
        self.spe.commit()
