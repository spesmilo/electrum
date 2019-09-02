package org.electroncash.electroncash3

import android.os.Build
import android.os.Handler
import android.util.Log
import android.view.Gravity
import android.view.WindowManager
import android.widget.Toast
import java.lang.reflect.Field
import java.lang.reflect.Modifier
import java.util.*


// Error messages are likely to be surprising, so give the user more time to read them.
val TOAST_DEFAULT_DURATION = Toast.LENGTH_LONG

// The default gravity of BOTTOM would show the toast over the keyboard if it's visible. If the
// keyboard color happens to be the same as the toast background, the user might not notice it
// at all.
val TOAST_DEFAULT_GRAVITY =  Gravity.CENTER


class ToastException(message: String?, cause: Throwable?,
                     val duration: Int = TOAST_DEFAULT_DURATION,
                     val gravity: Int = TOAST_DEFAULT_GRAVITY)
    : Exception(message, cause) {

    constructor(message: String?, duration: Int = TOAST_DEFAULT_DURATION,
                gravity: Int = TOAST_DEFAULT_GRAVITY)
        : this(message, null, duration, gravity)

    constructor(resId: Int, duration: Int = TOAST_DEFAULT_DURATION,
                gravity: Int = TOAST_DEFAULT_GRAVITY)
        : this(app.getString(resId), duration, gravity)

    constructor(cause: Throwable, duration: Int = TOAST_DEFAULT_DURATION,
                gravity: Int = TOAST_DEFAULT_GRAVITY)
        : this(cause.message, cause, duration, gravity)

    fun show() { toast(message!!, duration, gravity) }
}


// Prevent toasts repeated in quick succession from staying on screen for a long time. If a
// message has variable text, use the `key` argument to replace any existing toast with the
// same key.
//
// This cache is never cleared, but since it only contains references to the application context,
// this should be fine as long as the `key` argument is used where necessary.
val toastCache = HashMap<String, Toast>()

fun toast(text: CharSequence, duration: Int = TOAST_DEFAULT_DURATION,
          gravity: Int = TOAST_DEFAULT_GRAVITY, key: String? = null) {
    if (!onUiThread()) {
        runOnUiThread { toast(text, duration, gravity, key) }
    } else {
        val cacheKey = key ?: text.toString()
        toastCache.get(cacheKey)?.cancel()
        // Creating a new Toast each time is more robust than attempting to reuse the existing one.
        val toast = Toast.makeText(app, text, duration)
        toast.setGravity(gravity, 0, 0)
        toastCache.put(cacheKey, toast)
        if (Build.VERSION.SDK_INT == 25) {
            fixToastBug(toast)
        }
        toast.show()
    }
}

fun toast(resId: Int, duration: Int = TOAST_DEFAULT_DURATION,
          gravity: Int = TOAST_DEFAULT_GRAVITY, key: String? = null) {
    toast(app.getString(resId), duration, gravity, key)
}


// Workaround for Android 7.1 bug (Electron Cash issue #1528), based on
// https://github.com/cat9/ToastCompat.
private fun fixToastBug(toast: Toast) {
    try {
        val mTN = getFieldValue(toast, "mTN")!!
        val mHandler = getFieldValue(mTN, "mHandler") as Handler
        setFieldValue(mHandler, "mCallback", Handler.Callback {
            try {
                mHandler.handleMessage(it)
            } catch (e: WindowManager.BadTokenException) {}
            true
        })
    } catch (e: Exception) {
        Log.e("fixToastBug", "Workaround failed", e)
    }
}


private fun setFieldValue(obj: Any, name: String, value: Any?) {
    val field = getDeclaredField(obj, name)
    val accessFlags = field.getModifiers()
    if (Modifier.isFinal(accessFlags)) {
        val modifiersField = Field::class.java.getDeclaredField("accessFlags")
        modifiersField.setAccessible(true)
        modifiersField.setInt(field, field.getModifiers() and Modifier.FINAL.inv())
    }
    if (!field.isAccessible()) {
        field.setAccessible(true)
    }
    field.set(obj, value)
}

private fun getFieldValue(obj: Any, fieldName: String): Any? {
    val field = getDeclaredField(obj, fieldName)
    if (!field.isAccessible()) {
        field.setAccessible(true)
    }
    return field.get(obj)
}

private fun getDeclaredField(obj: Any, name: String): Field {
    var klass: Class<*>? = obj.javaClass
    while (klass != null) {
        try {
            return klass.getDeclaredField(name)
        } catch (e: NoSuchFieldException) {}
        klass = klass.superclass
    }
    throw IllegalArgumentException("Couldn't find field '$name' in object of type " +
                                   obj.javaClass.name)
}
