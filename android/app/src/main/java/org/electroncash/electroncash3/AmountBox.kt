package org.electroncash.electroncash3

import android.app.Dialog
import kotlinx.android.synthetic.main.amount_box.*


fun amountBoxGet(dialog: Dialog): Long {
    return toSatoshis(dialog.etAmount.text.toString())
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