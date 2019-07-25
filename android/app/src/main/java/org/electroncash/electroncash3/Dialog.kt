@file:Suppress("DEPRECATION")

package org.electroncash.electroncash3

import android.app.Dialog
import android.app.ProgressDialog
import android.arch.lifecycle.MutableLiveData
import android.arch.lifecycle.Observer
import android.arch.lifecycle.ViewModel
import android.arch.lifecycle.ViewModelProviders
import android.content.DialogInterface
import android.os.Bundle
import android.support.v4.app.DialogFragment
import android.support.v7.app.AlertDialog
import android.view.Menu
import android.view.MenuItem
import android.view.WindowManager
import android.widget.PopupMenu
import android.widget.Toast
import com.chaquo.python.PyException
import kotlinx.android.synthetic.main.password.*
import java.lang.IllegalArgumentException


abstract class AlertDialogFragment : DialogFragment() {
    class Model : ViewModel() {
        var started = false
    }
    private val model by lazy { ViewModelProviders.of(this).get(Model::class.java) }

    var started = false

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
        if (!started) {
            started = true
            onShowDialog(dialog as AlertDialog)
        }
        if (!model.started) {
            model.started = true
            onFirstShowDialog(dialog as AlertDialog)
        }
    }

    /** Can be used to do things like configure custom views, or attach listeners to buttons so
     *  they don't always close the dialog. */
    open fun onShowDialog(dialog: AlertDialog) {}

    /** Unlike onShowDialog, this will only be called once, even if the dialog is recreated
     * after a rotation. This can be used to do things like setting the initial state of
     * editable views. */
    open fun onFirstShowDialog(dialog: AlertDialog) {}
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
        onBuildDialog(builder, menu)

        val items = ArrayList<CharSequence>()
        var checkedItem: Int? = null
        for (i in 0 until menu.size()) {
            val item = menu.getItem(i)
            items.add(item.title)
            if (item.isChecked) {
                if (checkedItem != null) {
                    throw IllegalArgumentException("Menu has multiple checked items")
                }
                checkedItem = i
            }
        }

        val listener = DialogInterface.OnClickListener { _, index ->
            onMenuItemSelected(menu.getItem(index))
        }
        if (checkedItem == null) {
            builder.setItems(items.toTypedArray(), listener)
        } else {
            builder.setSingleChoiceItems(items.toTypedArray(), checkedItem, listener)
        }
    }

    abstract fun onBuildDialog(builder: AlertDialog.Builder, menu: Menu)
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


abstract class ProgressDialogTask<Result> : ProgressDialogFragment() {
    class Model : ViewModel() {
        val started = MutableLiveData<Unit>()
        val finished = MutableLiveData<Any?>()
    }
    private val model by lazy { ViewModelProviders.of(this).get(Model::class.java) }

    override fun onShowDialog(dialog: ProgressDialog) {
        if (model.started.value == null) {
            model.started.value = Unit
            Thread {
                model.finished.postValue(doInBackground())
            }.start()
        }
        model.finished.observe(this, Observer {
            dismiss()
            @Suppress("UNCHECKED_CAST")
            onPostExecute(it as Result)
        })
    }

    abstract fun doInBackground(): Result
    open fun onPostExecute(result: Result) {}
}


abstract class PasswordDialog(val runInBackground: Boolean = false) : AlertDialogFragment() {
    class Model : ViewModel() {
        val result = MutableLiveData<Boolean>()
    }
    private val model by lazy { ViewModelProviders.of(this).get(Model::class.java) }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        builder.setTitle(R.string.Enter_password)
            .setView(R.layout.password)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(android.R.string.cancel, null)
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val dialog = super.onCreateDialog(savedInstanceState)
        dialog.window!!.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE)
        return dialog
    }

    override fun onShowDialog(dialog: AlertDialog) {
        val posButton = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
        posButton.setOnClickListener {
            tryPassword(dialog.etPassword.text.toString())
        }
        dialog.etPassword.setOnEditorActionListener { _, _, _ ->
            posButton.performClick()
        }
        model.result.observe(this, Observer { onResult(it) })
    }

    fun tryPassword(password: String) {
        model.result.value = null
        val r = Runnable {
            try {
                try {
                    onPassword(password)
                    model.result.postValue(true)
                } catch (e: PyException) {
                    throw if (e.message!!.startsWith("InvalidPassword"))
                        ToastException(R.string.incorrect_password, Toast.LENGTH_SHORT) else e
                }
            } catch (e: ToastException) {
                e.show()
                model.result.postValue(false)
            }
        }
        if (runInBackground) {
            showDialog(activity!!, ProgressDialogFragment())
            Thread(r).start()
        } else {
            r.run()
        }
    }

    /** Attempt to perform the operation with the given password. If the operation fails, this
     * method should throw either a ToastException, or an InvalidPassword PyException (most
     * Python functions that take passwords will do this automatically). */
    abstract fun onPassword(password: String)

    private fun onResult(success: Boolean?) {
        if (success == null) return
        dismissDialog(activity!!, ProgressDialogFragment::class)
        if (success) {
            dismiss()
        }
    }
}
