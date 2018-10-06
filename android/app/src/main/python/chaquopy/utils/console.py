from __future__ import absolute_import, division, print_function

from io import TextIOBase
import sys
import threading

if sys.version_info[0] < 3:
    from Queue import Queue
else:
    from queue import Queue


def start_thread(runnable):
    threading.Thread(target=lambda: runnable.run()).start()


class ConsoleInputStream(TextIOBase):
    """Receives input in on_input in one thread (non-blocking), and provides a read interface in
    another thread (blocking). Reads will return bytes in Python 2 or unicode in Python 3.
    """
    def __init__(self, task):
        TextIOBase.__init__(self)
        self.task = task
        self.queue = Queue()
        self.buffer = ""
        self.eof = False

    @property
    def encoding(self):
        return "UTF-8"

    @property
    def errors(self):
        return "strict"  # UTF-8 encoding should never fail.

    def readable(self):
        return True

    def on_input(self, input):
        if self.eof:
            raise ValueError("Can't add more input after EOF")
        if input is None:
            self.eof = True
        self.queue.put(input)

    def read(self, size=None):
        if size is not None and size < 0:
            size = None
        buffer = self.buffer
        while (self.queue is not None) and ((size is None) or (len(buffer) < size)):
            if self.queue.empty():
                self.task.onInputState(True)
            input = self.queue.get()
            self.task.onInputState(False)
            if input is None:  # EOF
                self.queue = None
            else:
                buffer += input

        result = buffer if (size is None) else buffer[:size]
        self.buffer = buffer[len(result):]
        return result.encode(self.encoding, self.errors) if (sys.version_info[0] < 3) else result

    def readline(self, size=None):
        if size is not None and size < 0:
            size = None
        chars = []
        while (size is None) or (len(chars) < size):
            c = self.read(1)
            if not c:
                break
            chars.append(c)
            if c == "\n":
                break

        return "".join(chars)


class ConsoleOutputStream(TextIOBase):
    """Passes each write to the underlying stream, and also to the given method (which must take a
    single String argument) on the given Task object.
    """
    def __init__(self, task, method_name, stream):
        TextIOBase.__init__(self)
        self.stream = stream
        self.method = getattr(task, method_name)

    @property
    def encoding(self):
        return self.stream.encoding

    @property
    def errors(self):
        return self.stream.errors

    def writable(self):
        return True

    def write(self, s):
        if sys.version_info[0] < 3 and isinstance(s, str):
            u = s.decode(self.encoding, self.errors)
        else:
            u = s
        self.method(u)
        return self.stream.write(s)

    def flush(self):
        self.stream.flush()
