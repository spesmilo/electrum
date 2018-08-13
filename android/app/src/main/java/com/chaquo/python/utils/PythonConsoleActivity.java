package com.chaquo.python.utils;

import android.app.*;
import android.arch.lifecycle.*;
import android.os.*;
import android.util.*;
import com.chaquo.python.*;

/** Base class for a console-based activity that will run Python code. sys.stdout and sys.stderr
 * will be directed to the output view whenever the activity is resumed. If the Python code
 * caches their values, it can direct output to the activity even when it's paused.
 *
 * If STDIN_ENABLED is passed to the Task constructor, sys.stdin will also be redirected whenever
 * the activity is resumed. The input box will initially be hidden, and will be displayed the
 * first time sys.stdin is read. */
public abstract class PythonConsoleActivity extends ConsoleActivity {

    protected Task task;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        task = ViewModelProviders.of(this).get(getTaskClass());
    }

    protected abstract Class<? extends Task> getTaskClass();

    @Override protected void onResume() {
        task.resumeStreams();
        super.onResume();  // Starts the task thread.
    }

    @Override protected void onPause() {
        super.onPause();
        if (! isChangingConfigurations()) {
            task.pauseStreams();
        }
    }

    // =============================================================================================

    public static abstract class Task extends ConsoleActivity.Task {

        protected Python py = Python.getInstance();
        private PyObject sys;
        private PyObject stdin, stdout, stderr;
        private PyObject realStdin, realStdout, realStderr;

        public static final int STDIN_DISABLED = 0x0, STDIN_ENABLED = 0x1;

        public Task(Application app) { this(app, STDIN_ENABLED); }

        public Task(Application app, int flags) {
            super(app);
            sys = py.getModule("sys");
            PyObject console = py.getModule("chaquopy.utils.console");
            if ((flags & STDIN_ENABLED) != 0) {
                realStdin = sys.get("stdin");
                stdin = console.callAttr("ConsoleInputStream", this);
            }

            realStdout = sys.get("stdout");
            realStderr = sys.get("stderr");
            stdout = console.callAttr("ConsoleOutputStream", this, "output", realStdout);
            stderr = console.callAttr("ConsoleOutputStream", this, "outputError", realStderr);
        }

        /** Create the thread from Python rather than Java, otherwise user code may be surprised
         * to find its Python Thread object marked as "dummy" and "daemon". */
        @Override protected void startThread(Runnable runnable) {
            PyObject console = py.getModule("chaquopy.utils.console");
            console.callAttr("start_thread", runnable);
        }

        public void resumeStreams() {
            if (stdin != null) {
                sys.put("stdin", stdin);
            }
            sys.put("stdout", stdout);
            sys.put("stderr", stderr);
        }

        public void pauseStreams() {
            if (realStdin != null) {
                sys.put("stdin", realStdin);
            }
            sys.put("stdout", realStdout);
            sys.put("stderr", realStderr);
        }

        @SuppressWarnings("unused")  // Called from Python
        public void onInputState(boolean blocked) {
            if (blocked) {
                inputEnabled.postValue(true);
            }
        }

        @Override public void onInput(String text) {
            if (text != null) {
                // Messages which are empty (or only consist of newlines) will not be logged.
                Log.i("python.stdin", text.equals("\n") ? " " : text);
            }
            stdin.callAttr("on_input", text);
        }

        @Override protected void onCleared() {
            super.onCleared();
            if (stdin != null) {
                onInput(null);  // Signals EOF
            }
        }
    }

}
