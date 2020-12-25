package org.electroncash.electroncash3

import android.app.Dialog
import android.text.Editable
import android.view.View
import android.widget.EditText
import kotlinx.android.synthetic.main.amount_box.*


class AmountBox(val dialog: Dialog) {
    private val fiatEnabled = fiatEnabled()
    private var updating = false  // Prevent infinite recursion.
    var listener: (() -> Unit)? = null

    init {
        dialog.tvUnit.text = unitName
        if (fiatEnabled) {
            dialog.tvFiatUnit.text = formatFiatUnit()
        } else {
            dialog.tvFiatUnit.visibility = View.GONE
            dialog.etFiat.visibility = View.GONE
        }

        for (et in listOf(dialog.etAmount, dialog.etFiat)) {
            et.addAfterTextChangedListener { s: Editable ->
                if (!updating) {
                    if (fiatEnabled) {
                        val etOther: EditText
                        val formatOther: () -> String
                        when (et) {
                            dialog.etAmount -> {
                                etOther = dialog.etFiat
                                formatOther = {
                                    formatFiatAmount(toSatoshis(s.toString())) ?: ""
                                }
                            }
                            dialog.etFiat -> {
                                etOther = dialog.etAmount
                                formatOther = {
                                    val amount = fiatToSatoshis(s.toString())
                                    if (amount != null) formatSatoshis(amount) else ""
                                }
                            }
                            else -> throw RuntimeException("Unknown view")
                        }

                        try {
                            updating = true
                            etOther.setText(formatOther())
                            etOther.setSelection(etOther.text.length)
                        } catch (e: ToastException) {
                            etOther.setText("")
                        } finally {
                            updating = false
                        }
                    }
                    listener?.invoke()
                }
            }
        }
    }

    var amount: Long?
        get() {
            val amount = try {
                toSatoshis(dialog.etAmount.text.toString())
            } catch (e: ToastException) {
                return null
            }
            // Both the Send and Request dialogs require a positive number.
            return if (amount <= 0) null else amount
        }
        set(amount) {
            if (amount == null) {
                dialog.etAmount.setText("")
            } else {
                dialog.etAmount.setText(formatSatoshis(amount))
                dialog.etAmount.setSelection(dialog.etAmount.text.length)
            }
        }

    var isEditable: Boolean
        get() = isEditable(dialog.etAmount)
        set(editable) {
            for (et in listOf(dialog.etAmount, dialog.etFiat)) {
                setEditable(et, editable)
            }
        }

    /** We don't <requestFocus/> in the layout file, because in the Send dialog, initial focus
     * is normally on the address box. */
    fun requestFocus() = dialog.etAmount.requestFocus()
}
