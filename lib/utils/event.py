import weakref

# Based on: https://stackoverflow.com/a/2022629
# By Longpoke (https://stackoverflow.com/users/80243)
class Event(list):
    """Event subscription.

    A list of callable objects. Calling an instance of this will cause a
    call to each item in the list in ascending order by index.

    The list can also contain WeakMethods using the append_weak and
    insert_weak methods. When a weak method is dead, it will be removed
    from the list the next time the event is called.

    Example Usage:
    >>> def f(x):
    ...     print 'f(%s)' % x
    >>> def g(x):
    ...     print 'g(%s)' % x
    >>> e = Event()
    >>> e()
    >>> e.append(f)
    >>> e(123)
    f(123)
    >>> e.remove(f)
    >>> e()
    >>> e += (f, g)
    >>> e(10)
    f(10)
    g(10)
    >>> del e[0]
    >>> e(2)
    g(2)

    """
    def __call__(self, *args, **kwargs):
        # Holds dead weak methods to remove
        dead_methods = []

        for method in self:
            if isinstance(method, weakref.WeakMethod):
                method = method()
                if not method:
                    # This weak reference is dead, remove it from the list
                    dead_methods.append(method)
                    continue
            method(*args, **kwargs)

        # Remove all dead methods
        for dead_method in dead_methods:
            self.remove(dead_method)

    def __repr__(self):
        return "Event(%s)" % list.__repr__(self)

    @staticmethod
    def make_weak(method) -> weakref.WeakMethod:
        return weakref.WeakMethod(method)

    def append_weak(self, method):
        self.append(Event.make_weak(method))

    def insert_weak(self, pos, method):
        self.insert(pos, Event.make_weak(method))
