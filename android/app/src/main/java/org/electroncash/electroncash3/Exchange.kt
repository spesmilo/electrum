package org.electroncash.electroncash3

import androidx.lifecycle.MediatorLiveData
import com.chaquo.python.Kwarg


val EXCHANGE_CALLBACKS = setOf("on_quotes", "on_history")

val libExchange by lazy { libMod("exchange_rate") }
val fiatUpdate = MediatorLiveData<Unit>().apply { value = Unit }

val fx by lazy { daemonModel.daemon.get("fx")!! }


fun initExchange() {
    settings.getString("currency").observeForever {
        fx.callAttr("set_currency", it)
    }
    settings.getString("use_exchange").observeForever {
        fx.callAttr("set_exchange", it)
    }

    with (fiatUpdate) {
        addSource(settings.getBoolean("use_exchange_rate"), { value = Unit })
        addSource(settings.getString("currency"), { value = Unit })
        addSource(settings.getString("use_exchange"), { value = Unit })
    }
}


fun fiatEnabled() = fx.callAttr("is_enabled").toBoolean()


fun fiatToSatoshis(s: String): Long? {
    if (!fiatEnabled()) return null
    try {
        // toDouble accepts only the English number format: see comment in Util.kt.
        return fx.callAttr("fiat_to_amount", s.toDouble()).toLong()
    } catch (e: NumberFormatException) {
        throw ToastException(R.string.Invalid_amount)
    }
}


fun formatSatoshisAndFiat(amount: Long): String {
    var result = formatSatoshisAndUnit(amount)
    val fiat = formatFiatAmount(amount)
    if (fiat != null) {
        result += " ($fiat ${formatFiatUnit()})"
    }
    return result
}

fun formatFiatAmount(amount: Long): String? {
    if (!fiatEnabled()) return null
    val amountStr = fx.callAttr("format_amount", amount, Kwarg("commas", false)).toString()
    return if (amountStr.isEmpty()) null else amountStr
}


fun formatFiatUnit(): String {
    return fx.callAttr("get_currency").toString()
}