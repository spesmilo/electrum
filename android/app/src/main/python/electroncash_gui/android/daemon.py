def make_callback(daemon_model):
    return lambda event, *args: daemon_model.onCallback(event)
