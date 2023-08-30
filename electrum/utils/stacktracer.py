#!/usr/bin/env python
#
# Copyright (C) 2010 Laszlo Nagy (nagylzs)
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Taken from: https://code.activestate.com/recipes/577334-how-to-debug-deadlocked-multi-threaded-programs/


"""Stack tracer for multi-threaded applications.
Useful for debugging deadlocks and hangs.

Usage:
    import stacktracer
    stacktracer.trace_start("trace.html", interval=5)
    ...
    stacktracer.trace_stop()

This will create a file named "trace.html" showing the stack traces of all threads,
updated every 5 seconds.
"""

import os
import sys
import threading
import time
import traceback
from typing import Optional

# 3rd-party dependency:
from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter


def _thread_from_id(ident) -> Optional[threading.Thread]:
    return threading._active.get(ident)


def stacktraces():
    """Taken from http://bzimmer.ziclix.com/2008/12/17/python-thread-dumps/"""
    code = []
    for thread_id, stack in sys._current_frames().items():
        thread = _thread_from_id(thread_id)
        code.append(f"\n# thread_id={thread_id}. thread={thread}")
        for filename, lineno, name, line in traceback.extract_stack(stack):
            code.append(f'File: "{filename}", line {lineno}, in {name}')
            if line:
                code.append("  %s" % (line.strip()))

    return highlight("\n".join(code), PythonLexer(), HtmlFormatter(
        full=False,
        # style="native",
        noclasses=True,
    ))


class TraceDumper(threading.Thread):
    """Dump stack traces into a given file periodically.

    # written by nagylzs
    """

    def __init__(self, fpath, interval, auto):
        """
        @param fpath: File path to output HTML (stack trace file)
        @param auto: Set flag (True) to update trace continuously.
            Clear flag (False) to update only if file not exists.
            (Then delete the file to force update.)
        @param interval: In seconds: how often to update the trace file.
        """
        assert (interval > 0.1)
        self.auto = auto
        self.interval = interval
        self.fpath = os.path.abspath(fpath)
        self.stop_requested = threading.Event()
        threading.Thread.__init__(self)

    def run(self):
        while not self.stop_requested.is_set():
            time.sleep(self.interval)
            if self.auto or not os.path.isfile(self.fpath):
                self.dump_stacktraces()

    def stop(self):
        self.stop_requested.set()
        self.join()
        try:
            if os.path.isfile(self.fpath):
                os.unlink(self.fpath)
        except OSError:
            pass

    def dump_stacktraces(self):
        with open(self.fpath, "w+") as fout:
            fout.write(stacktraces())


_tracer = None  # type: Optional[TraceDumper]


def trace_start(fpath, interval=5, *, auto=True):
    """Start tracing into the given file."""
    global _tracer
    if _tracer is None:
        _tracer = TraceDumper(fpath, interval, auto)
        _tracer.daemon = True
        _tracer.start()
    else:
        raise Exception("Already tracing to %s" % _tracer.fpath)


def trace_stop():
    """Stop tracing."""
    global _tracer
    if _tracer is None:
        raise Exception("Not tracing, cannot stop.")
    else:
        _tracer.stop()
        _tracer = None
