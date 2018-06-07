""" This module allows for the registration of callbacks.
Allowing interested objects to be notified of certain events.
"""

from collections import defaultdict
import threading


class Triggers:
    def __init__(self):
        # callbacks set by the GUI
        self.callbacks = defaultdict(list)
        self.trigger_lock = threading.Lock()

    def register_callback(self, callback, events):
        with self.trigger_lock:
            for event in events:
                self.callbacks[event].append(callback)

    def unregister_callback(self, callback):
        with self.trigger_lock:
            for callbacks in self.callbacks.values():
                if callback in callbacks:
                    callbacks.remove(callback)

    def trigger_callback(self, event, *args):
        with self.trigger_lock:
            callbacks = self.callbacks[event][:]
        [callback(event, *args) for callback in callbacks]
