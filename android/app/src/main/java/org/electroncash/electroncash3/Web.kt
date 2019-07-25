package org.electroncash.electroncash3

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import com.chaquo.python.PyObject


val libWeb by lazy { libMod("web") }


fun exploreAddress(activity: Activity, addr: PyObject) {
    openBrowser(activity, libWeb.callAttr("BE_URL", daemonModel.config,
                                          "addr", addr).toString())
}


fun exploreTransaction(activity: Activity, txid: String) {
    openBrowser(activity, libWeb.callAttr("BE_URL", daemonModel.config,
                                          "tx", txid).toString())
}


fun openBrowser(activity: Activity, url: String) {
    try {
        activity.startActivity(Intent(Intent.ACTION_VIEW).apply {
            data = Uri.parse(url)
        })
    } catch (e: ActivityNotFoundException) {
        toast(e.message!!)
    }
}