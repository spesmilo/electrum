package org.electroncash.electroncash3

import android.arch.lifecycle.MediatorLiveData


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


fun formatFiatAmountAndUnit(amount: Long): String? {
    val amountStr = formatFiatAmount(amount)
    if (amountStr == null) {
        return null
    } else {
        return amountStr + " " + formatFiatUnit()
    }
}


fun formatFiatAmount(amount: Long): String? {
    if (!fx.callAttr("is_enabled").toBoolean()) {
        return null
    }
    val amountStr = fx.callAttr("format_amount", amount).toString()
    return if (amountStr.isEmpty()) null else amountStr
}


fun formatFiatUnit(): String {
    return fx.callAttr("get_currency").toString()
}