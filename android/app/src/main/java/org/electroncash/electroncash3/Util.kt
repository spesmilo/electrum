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
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.PopupMenu
import android.widget.Toast
import java.lang.IllegalArgumentException
import java.util.*
import kotlin.reflect.KClass


val UNIT_BCH = 100000000L
val UNIT_MBCH = 100000L
var unitSize = UNIT_BCH  // TODO: make unit configurable
var unitName = "BCH"     //

val libBitcoin by lazy { libMod("bitcoin") }
val libUtil by lazy { libMod("util") }


fun toSatoshis(s: String, unit: Long = unitSize) : Long {
    if (s.isEmpty()) {
        throw ToastException(R.string.enter_amount)
    }
    try {
        return Math.round(s.toDouble() * unit)
    } catch (e: NumberFormatException) {
        throw ToastException(R.string.Invalid_amount)
    }
}

// We use Locale.US to be consistent with lib/exchange_rate.py, which is also locale-insensitive.
fun formatSatoshis(amount: Long, unit: Long = unitSize): String {
    val places = Math.log10(unit.toDouble()).toInt()
    var result = "%.${places}f".format(Locale.US, amount.toDouble() / unit).trimEnd('0')
    if (result.endsWith(".")) {
        result += "0"
    }
    return result
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


fun copyToClipboard(text: CharSequence) {
    @Suppress("DEPRECATION")
    (getSystemService(ClipboardManager::class)).text = text
    toast(R.string.text_copied_to_clipboard)
}


fun <T: Any> getSystemService(kcls: KClass<T>): T {
    return ContextCompat.getSystemService(app, kcls.java)!!
}


fun setupVerticalList(rv: RecyclerView) {
    rv.layoutManager = LinearLayoutManager(rv.context)
    rv.addItemDecoration(DividerItemDecoration(rv.context, DividerItemDecoration.VERTICAL))

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
        : this(context, inflateMenu(context, menuId))

    override fun getItemId(position: Int): Long {
        return menu.getItem(position).itemId.toLong()
    }
}

fun inflateMenu(context: Context, menuId: Int) : Menu {
    val menu = PopupMenu(context, null).menu
    MenuInflater(context).inflate(menuId, menu)
    return menu
}

private fun menuToList(menu: Menu): List<String> {
    val result = ArrayList<String>()
    for (i in 0 until menu.size()) {
        result.add(menu.getItem(i).title.toString())
    }
    return result
}