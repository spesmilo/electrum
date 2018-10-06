package org.electroncash.electroncash3

import android.app.NotificationManager
import android.content.ClipboardManager
import android.content.Context
import android.databinding.DataBindingUtil
import android.databinding.ViewDataBinding
import android.support.v4.app.DialogFragment
import android.support.v4.app.FragmentActivity
import android.support.v4.content.ContextCompat
import android.support.v7.widget.RecyclerView
import android.view.LayoutInflater
import android.view.ViewGroup
import android.view.inputmethod.InputMethodManager
import android.widget.Toast
import kotlin.reflect.KClass


val UNIT_BCH = 100000000L
val UNIT_MBCH = 100000L
var unitSize = UNIT_BCH  // TODO: make unit configurable
var unitName = "BCH"     //

fun toSatoshis(s: String, unit: Long = unitSize) : Long? {
    try {
        return Math.round(s.toDouble() * unit)
    } catch (e: NumberFormatException) { return null }
}

fun formatSatoshis(amount: Long, unit: Long = unitSize): String {
    val places = Math.log10(unit.toDouble()).toInt()
    return "%.${places}f".format(amount.toDouble() / unit)
}


fun showDialog(activity: FragmentActivity, frag: DialogFragment) {
    val fm = activity.supportFragmentManager
    val tag = frag.javaClass.simpleName
    if (fm.findFragmentByTag(tag) == null) {
        frag.show(fm, tag)
    }
}

fun <T: DialogFragment> dismissDialog(activity: FragmentActivity, fragClass: KClass<T>) {
    val frag = activity.supportFragmentManager.findFragmentByTag(fragClass.java.simpleName)
    (frag as DialogFragment?)?.dismiss()
}


// Since error messages are likely to be surprising, set the default duration to long.
class ToastException(message: String, val duration: Int = Toast.LENGTH_LONG)
    : Exception(message) {

    constructor(resId: Int, duration: Int = Toast.LENGTH_LONG)
        : this(app.getString(resId), duration)

    fun show() { toast(message!!, duration) }
}


// Prevent toasts repeated in quick succession from staying on screen for a long time. If a
// message has variable text, use the `key` argument to replace any existing toast with the
// same key.
//
// This cache is never cleared, but since it only contains references to the application context,
// this should be fine as long as the `key` argument is used where necessary.
val toastCache = HashMap<String, Toast>()

fun toast(text: CharSequence, duration: Int = Toast.LENGTH_SHORT, key: String? = null) {
    if (!onUiThread()) {
        runOnUiThread { toast(text, duration, key) }
    } else {
        val cacheKey = key ?: text.toString()
        toastCache.get(cacheKey)?.cancel()
        // Creating a new Toast each time is more robust than attempting to reuse the existing one.
        val toast = Toast.makeText(app, text, duration)
        toastCache.put(cacheKey, toast)
        toast.show()
    }
}

fun toast(resId: Int, duration: Int = Toast.LENGTH_SHORT, key: String? = null) {
    toast(app.getString(resId), duration, key)
}


val SERVICES = mapOf(
    ClipboardManager::class to Context.CLIPBOARD_SERVICE,
    InputMethodManager::class to Context.INPUT_METHOD_SERVICE,
    NotificationManager::class to Context.NOTIFICATION_SERVICE
)

fun <T: Any> getSystemService(kcls: KClass<T>): T {
    // TODO: do this once we move to support library version 28 (28.0.0-rc02 breaks the layout
    // editor in Android Studio 3.1):
    // return ContextCompat.getSystemService(app, kcls.java)!!
    return app.getSystemService(SERVICES.get(kcls)!!) as T
}


// Based on https://medium.com/google-developers/android-data-binding-recyclerview-db7c40d9f0e4
abstract class BoundAdapter<Model: Any>(val layoutId: Int)
    : RecyclerView.Adapter<BoundViewHolder<Model>>() {

    override fun getItemViewType(position: Int): Int {
        return layoutId
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): BoundViewHolder<Model> {
        val layoutInflater = LayoutInflater.from(parent.context)
        val binding = DataBindingUtil.inflate<ViewDataBinding>(
            layoutInflater, viewType, parent, false)
        return BoundViewHolder(binding)
    }

    override fun onBindViewHolder(holder: BoundViewHolder<Model>, position: Int) {
        holder.item = getItem(position)
        holder.binding.setVariable(BR.model, holder.item)
        holder.binding.executePendingBindings()
    }

    protected abstract fun getItem(position: Int): Model
}

class BoundViewHolder<Model: Any>(val binding: ViewDataBinding)
    : RecyclerView.ViewHolder(binding.root) {

    lateinit var item: Model
}
