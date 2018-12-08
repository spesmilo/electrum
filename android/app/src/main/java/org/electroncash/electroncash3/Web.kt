package org.electroncash.electroncash3

import android.app.Activity
import android.content.Intent
import android.net.Uri


val libWeb by lazy { libMod("web") }


fun exploreAddress(activity: Activity, address: String) {
    val addressObj = clsAddress.callAttr("from_string", address)
    openBrowser(activity, libWeb.callAttr("BE_URL", daemonModel.config,
                                          "addr", addressObj).toString())
}


fun exploreTransaction(activity: Activity, txid: String) {
    openBrowser(activity, libWeb.callAttr("BE_URL", daemonModel.config,
                                          "tx", txid).toString())
}


fun openBrowser(activity: Activity, url: String) {
    activity.startActivity(Intent(Intent.ACTION_VIEW).apply {
        data = Uri.parse(url)
    })
}