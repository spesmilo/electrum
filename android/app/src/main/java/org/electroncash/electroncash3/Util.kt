package org.electroncash.electroncash3

import android.content.ClipboardManager
import android.content.Context
import android.text.Editable
import android.text.TextWatcher
import android.view.ContextThemeWrapper
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.PopupMenu
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.core.os.ConfigurationCompat
import androidx.core.text.BidiFormatter
import androidx.core.text.TextDirectionHeuristicsCompat
import androidx.databinding.DataBindingUtil
import androidx.databinding.ViewDataBinding
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.util.*
import kotlin.reflect.KClass


val libBitcoin by lazy { libMod("bitcoin") }
val libUtil by lazy { libMod("util") }

// See Settings.kt
var unitName = ""
var unitPlaces = 0


lateinit var bidi: BidiFormatter

fun setLocale(context: Context) {
    val locale = ConfigurationCompat.getLocales(context.resources.configuration).get(0)
    libMod("i18n").callAttr("set_language", locale.toString())
    bidi = BidiFormatter.getInstance(locale)
}

// Concatenating or nesting the return values of this function doesn't always give the desired
// result, so it's best to call it immediately before passing the text to the UI.
fun ltr(s: String) = bidi.unicodeWrap(s, TextDirectionHeuristicsCompat.LTR)!!


// When converting values to and from strings, we only accept and produce the English number
// format with a dot as the decimal point, and no thousands separators. This is consistent with
// all the string conversion functions in the back end.
//
// When an EditText is set to inputType="numberDecimal", the EditText only allows the user to
// enter digits and at most one dot. The device locale doesn't seem to make a difference: even
// if the locale uses a comma as the decimal point, the EditText still only accepts a dot. See
// https://issuetracker.google.com/issues/36907764, 70008222 and 172776283.

fun toSatoshis(s: String) : Long {
    val unit = Math.pow(10.0, unitPlaces.toDouble())
    try {
        // toDouble accepts only the English number format: see comment above.
        return Math.round(s.toDouble() * unit)
    } catch (e: NumberFormatException) {
        throw ToastException(R.string.Invalid_amount)
    }
}

@JvmOverloads  // For data binding.
fun formatSatoshis(amount: Long, signed: Boolean = false): String {
    val unit = Math.pow(10.0, unitPlaces.toDouble())
    // Locale.US produces the English number format: see comment above.
    var result = "%${if (signed) "+" else ""}.${unitPlaces}f"
        .format(Locale.US, amount / unit).trimEnd('0')
    if (result.endsWith(".")) {
        result += "0"
    }
    return result
}

fun formatSatoshisAndUnit(amount: Long?, signed: Boolean = false): String =
    if (amount == null) app.getString(R.string.Unknown)
    else "${formatSatoshis(amount, signed)} $unitName"

fun formatTime(time: Long?): String =
    if (time in listOf(null, 0L)) app.getString(R.string.Unknown)
    else libUtil.callAttr("format_time", time).toString()


fun Context.getQuantityString(id: Int, quantity: Int, vararg args: Any) =
    resources.getQuantityString(id, quantity, *args)

// For where the quantity is also the single placeholder.
fun Context.getQuantityString1(id: Int, quantity: Int) =
    getQuantityString(id, quantity, quantity)


fun showDialog(target: Fragment, frag: DialogFragment) {
    showDialog(target.activity!!, frag, target)
}

fun showDialog(activity: FragmentActivity, frag: DialogFragment, target: Fragment? = null) {
    val fm = activity.supportFragmentManager
    val tag = frag::class.java.name
    if (fm.findFragmentByTag(tag) == null) {
        if (target != null) {
            frag.setTargetFragment(target, 0)
        }
        frag.showNow(fm, tag)
    }
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


fun EditText.addAfterTextChangedListener(listener: (Editable) -> Unit) {
    addTextChangedListener(object : TextWatcher {
        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        override fun afterTextChanged(s: Editable) {
            listener(s)
        }
    })
}


/** Enables or disables an EditText without changing its appearance. */
fun setEditable(et: EditText, editable: Boolean) {
    if (editable) {
        // Implicitly calls setFocusable(true).
        et.setFocusableInTouchMode(true)
    } else {
        // Implicitly calls setFocusableInTouchMode(false).
        et.setFocusable(false)
    }
}

fun isEditable(et: EditText) = et.isFocusable()


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
