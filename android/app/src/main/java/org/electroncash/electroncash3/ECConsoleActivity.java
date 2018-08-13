package org.electroncash.electroncash3;

import android.app.*;
import android.os.*;
import android.text.*;
import android.widget.*;
import com.chaquo.python.utils.*;

public class ECConsoleActivity extends PythonConsoleActivity {

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // VISIBLE_PASSWORD is necessary to prevent some versions of the Google keyboard from
        // displaying the suggestion bar.
        ((TextView) findViewById(resId("id", "etInput"))).setInputType(
            InputType.TYPE_CLASS_TEXT +
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS +
            InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
    }

    @Override protected Class<? extends Task> getTaskClass() {
        return Task.class;
    }

    // Maintain REPL state unless the loop has been terminated, e.g. by typing `exit()`. Will
    // also hide previous activities in the back-stack, unless the activity is in its own task.
    @Override public void onBackPressed() {
        if (task.getState() == Thread.State.RUNNABLE) {
            moveTaskToBack(true);
        } else {
            super.onBackPressed();
        }
    }

    // =============================================================================================

    public static class Task extends PythonConsoleActivity.Task {
        public Task(Application app) {
            super(app);
        }

        @Override public void run() {
            py.getModule("electroncash_gui.android.ec_console")
                .callAttr("ECConsole", getApplication())
                .callAttr("interact");
        }
    }

}
