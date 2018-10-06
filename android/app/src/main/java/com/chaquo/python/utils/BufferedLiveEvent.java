package com.chaquo.python.utils;

import android.os.*;
import android.support.annotation.*;
import java.util.*;

/** Similar to SimpleLiveEvent, but any values set while inactive will be buffered. As soon as
 * we have an active observer, it will be notified of those values in the same order as they were
 * set. */
public class BufferedLiveEvent<T> extends SingleLiveEvent<T> {

    private ArrayList<T> mBuffer = new ArrayList<>();
    private Handler mHandler;

    /** Unlike in the base class, multiple calls to postData will always result in multiple values
     * being notified to the observer. */
    @Override public void postValue(@Nullable final T value) {
        // Delay initialization for unit tests.
        if (mHandler == null) {
            mHandler = new Handler(Looper.getMainLooper());
        }
        mHandler.post(new Runnable() {
            @Override public void run() {
                setValue(value);
            }
        });
    }

    @Override public void setValue(@Nullable T t) {
        if (hasActiveObservers() && mBuffer.isEmpty()) {  // See onActive
            super.setValue(t);
        } else {
            mBuffer.add(t);
        }
    }

    @Override protected void onActive() {
        // Don't use a foreach loop, an observer might call setValue and lengthen the buffer.
        for (int i = 0; i < mBuffer.size(); i++) {
            super.setValue(mBuffer.get(i));
        }
        mBuffer.clear();
    }

}
