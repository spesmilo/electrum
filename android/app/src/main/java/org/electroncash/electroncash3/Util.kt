package org.electroncash.electroncash3

import android.content.ClipboardManager
import android.content.Context
import android.databinding.DataBindingUtil
import android.databinding.ViewDataBinding
import android.support.v4.app.DialogFragment
import android.support.v4.app.FragmentActivity
import android.support.v4.content.ContextCompat
import android.support.v7.widget.DividerItemDecoration
import android.support.v7.widget.LinearLayoutManager
import android.support.v7.widget.RecyclerView
import android.view.ContextThemeWrapper
import android.view.Gravity
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.PopupMenu
import android.widget.Toast
import java.util.*
import kotlin.reflect.KClass


val libBitcoin by lazy { libMod("bitcoin") }
val libUtil by lazy { libMod("util") }


// See Settings.kt
var unitName = ""
var unitPlaces = 0


fun toSatoshis(s: String, places: Int = unitPlaces) : Long {
    val unit = Math.pow(10.0, places.toDouble())
    try {
        return Math.round(s.toDouble() * unit)
    } catch (e: NumberFormatException) {
        throw ToastException(R.string.Invalid_amount)
    }
}

// We use Locale.US to be consistent with lib/exchange_rate.py, which is also locale-insensitive.
@JvmOverloads  // For data binding call in address_list.xml.
fun formatSatoshis(amount: Long, places: Int = unitPlaces): String {
    val unit = Math.pow(10.0, places.toDouble())
    var result = "%.${places}f".format(Locale.US, amount / unit).trimEnd('0')
    if (result.endsWith(".")) {
        result += "0"
    }
    return result
}

fun formatSatoshisAndUnit(amount: Long): String {
    return "${formatSatoshis(amount)} $unitName"
}


fun showDialog(activity: FragmentActivity, frag: DialogFragment) {
    val fm = activity.supportFragmentManager
    val tag = frag::class.java.name
    if (fm.findFragmentByTag(tag) == null) {
        frag.show(fm, tag)
    }
}

fun <T: DialogFragment> dismissDialog(activity: FragmentActivity, fragClass: KClass<T>) {
    findDialog(activity, fragClass)?.dismiss()
}

fun <T: DialogFragment> findDialog(activity: FragmentActivity, fragClass: KClass<T>) : T? {
    val tag = fragClass.java.name
    val frag = activity.supportFragmentManager.findFragmentByTag(tag)
    if (frag == null) {
        return null
    } else if (frag::class != fragClass) {
        throw ClassCastException(
            "Expected ${fragClass.java.name}, got ${frag::class.java.name}")
    } else {
        @Suppress("UNCHECKED_CAST")
        return frag as T?
    }
}


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
        toast.show()
    }
}

fun toast(resId: Int, duration: Int = TOAST_DEFAULT_DURATION,
          gravity: Int = TOAST_DEFAULT_GRAVITY, key: String? = null) {
    toast(app.getString(resId), duration, gravity, key)
}


fun copyToClipboard(text: CharSequence, what: Int? = null) {
    @Suppress("DEPRECATION")
    (getSystemService(ClipboardManager::class)).text = text
    val message = if (what == null) app.getString(R.string.text_copied)
                  else app.getString(R.string._s_copied, app.getString(what))
    toast(message, Toast.LENGTH_SHORT)
}


fun <T: Any> getSystemService(kcls: KClass<T>): T {
    return ContextCompat.getSystemService(app, kcls.java)!!
}


fun setupVerticalList(rv: RecyclerView) {
    rv.layoutManager = LinearLayoutManager(rv.context)

    // Dialog theme has listDivider set to null, so use the base app theme instead.
    rv.addItemDecoration(
        DividerItemDecoration(ContextThemeWrapper(rv.context, R.style.AppTheme),
                              DividerItemDecoration.VERTICAL))
}


// The RecyclerView ListAdapter gives some nice animations when the list changes, but I found
// the diff process was too slow when comparing long transaction lists. However, we do emulate
// its API here in case we try it again in the future.
open class BoundAdapter<T: Any>(val layoutId: Int)
    : RecyclerView.Adapter<BoundViewHolder<T>>() {

    var list: List<T> = listOf()

    fun submitList(newList: List<T>?) {
        list = newList ?: listOf()
        notifyDataSetChanged()
    }

    override fun getItemCount() =
        list.size

    fun getItem(position: Int) =
        list.get(position)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): BoundViewHolder<T> {
        val layoutInflater = LayoutInflater.from(parent.context)
        val binding = DataBindingUtil.inflate<ViewDataBinding>(
            layoutInflater, layoutId, parent, false)
        return BoundViewHolder(binding)
    }

    override fun onBindViewHolder(holder: BoundViewHolder<T>, position: Int) {
        holder.item = getItem(position)
        holder.binding.setVariable(BR.model, holder.item)
        holder.binding.executePendingBindings()
    }
}

class BoundViewHolder<T: Any>(val binding: ViewDataBinding)
    : RecyclerView.ViewHolder(binding.root) {

    lateinit var item: T
}


class MenuAdapter(context: Context, val menu: Menu)
    : ArrayAdapter<String>(context, android.R.layout.simple_spinner_item, menuToList(menu)) {
    init {
        if (context === app) {
            // This resulted in white-on-white text on older API levels (e.g. 18).
            throw IllegalArgumentException(
                "Can't use application context: theme will not be applied to views")
        }
        setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
    }

    constructor(context: Context, menuId: Int)
        : this(context, inflateMenu(menuId))

    override fun getItemId(position: Int): Long {
        return menu.getItem(position).itemId.toLong()
    }
}

fun inflateMenu(menuId: Int) : Menu {
    val menu = PopupMenu(app, null).menu
    MenuInflater(app).inflate(menuId, menu)
    return menu
}

private fun menuToList(menu: Menu): List<String> {
    val result = ArrayList<String>()
    for (i in 0 until menu.size()) {
        result.add(menu.getItem(i).title.toString())
    }
    return result
}