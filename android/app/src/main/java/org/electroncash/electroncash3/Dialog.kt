@file:Suppress("DEPRECATION")

package org.electroncash.electroncash3

import android.app.Dialog
import android.app.ProgressDialog
import android.arch.lifecycle.MutableLiveData
import android.arch.lifecycle.Observer
import android.arch.lifecycle.ViewModel
import android.arch.lifecycle.ViewModelProviders
import android.os.Bundle
import android.support.v4.app.DialogFragment
import android.support.v7.app.AlertDialog
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.widget.PopupMenu


abstract class AlertDialogFragment : DialogFragment() {
    var firstStart = true

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val builder = AlertDialog.Builder(context!!)
        onBuildDialog(builder)
        return builder.create()
    }

    open fun onBuildDialog(builder: AlertDialog.Builder) {}

    // We used to trigger onShowDialog from Dialog.setOnShowListener, but we had crash reports
    // indicating that the fragment context was sometimes null in that listener (#1046, #1108).
    // So use one of the fragment lifecycle methods instead.
    override fun onStart() {
        super.onStart()
        if (firstStart) {
            firstStart = false
            onShowDialog(dialog as AlertDialog)
        }
    }

    /** Can be used to do things like configure custom views, or attach listeners to buttons so
     *  they don't always close the dialog. */
    open fun onShowDialog(dialog: AlertDialog) {}
}


class MessageDialog() : AlertDialogFragment() {
    constructor(title: String, message: String) : this() {
        arguments = Bundle().apply {
            putString("title", title)
            putString("message", message)
        }
    }
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(arguments!!.getString("title"))
            .setMessage(arguments!!.getString("message"))
            .setPositiveButton(android.R.string.ok, null)
    }
}


abstract class MenuDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        val menu = PopupMenu(app, null).menu
        onBuildDialog(builder, menu, MenuInflater(app))
        val items = Array(menu.size()) {
            menu.getItem(it).title
        }
        builder.setItems(items) { _, index ->
            onMenuItemSelected(menu.getItem(index))
        }
    }

    abstract fun onBuildDialog(builder: AlertDialog.Builder, menu: Menu,
                               inflater: MenuInflater)
    abstract fun onMenuItemSelected(item: MenuItem)
}


open class ProgressDialogFragment : DialogFragment() {
    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        isCancelable = false
        val dialog = ProgressDialog(context).apply {
            setMessage(getString(R.string.please_wait))
        }
        dialog.setOnShowListener { onShowDialog(dialog) }
        return dialog
    }

    open fun onShowDialog(dialog: ProgressDialog) {}
}


abstract class ProgressDialogTask : ProgressDialogFragment() {
    class Model : ViewModel() {
        val started = MutableLiveData<Unit>()
        val finished = MutableLiveData<Unit>()
    }
    private val model by lazy { ViewModelProviders.of(this).get(Model::class.java) }

    override fun onShowDialog(dialog: ProgressDialog) {
        if (model.started.value == null) {
            model.started.value = Unit
            Thread {
                doInBackground()
                model.finished.postValue(Unit)
            }.start()
        }
        model.finished.observe(this, Observer {
            dismiss()
        })
    }

    abstract fun doInBackground()
}
