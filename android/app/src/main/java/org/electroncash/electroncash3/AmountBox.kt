package org.electroncash.electroncash3

import android.app.Dialog
import android.widget.Toast
import kotlinx.android.synthetic.main.amount_box.*


fun amountBoxGet(dialog: Dialog): Long {
    val amount = toSatoshis(dialog.etAmount.text.toString())
    if (amount <= 0) throw ToastException(R.string.Invalid_amount, Toast.LENGTH_SHORT)
    return amount
}


fun amountBoxUpdate(dialog: Dialog) {
    var fiatAmount = ""
    var fiatUnit = ""
    try {
        val fiat = formatFiatAmount(amountBoxGet(dialog))
        if (fiat != null) {
            fiatAmount = fiat
            fiatUnit = formatFiatUnit()
        }
    } catch (e: ToastException) {}
    dialog.tvFiat.setText(fiatAmount)
    dialog.tvFiatUnit.setText(fiatUnit)
}