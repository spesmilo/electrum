package org.electroncash.electroncash3

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import com.chaquo.python.Kwarg
import com.chaquo.python.PyObject
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.android.synthetic.main.contact_detail.*
import kotlinx.android.synthetic.main.contacts.*

val guiContacts by lazy { guiMod("contacts") }
val libContacts by lazy { libMod("contacts") }


class ContactsFragment : ListFragment(R.layout.contacts, R.id.rvContacts) {

    override fun onListModelCreated(listModel: ListModel) {
        with (listModel) {
            trigger.addSource(daemonUpdate)
            trigger.addSource(settings.getBoolean("cashaddr_format"))
            data.function = { guiContacts.callAttr("get_contacts", wallet)!! }
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        btnAdd.setOnClickListener { showDialog(this, ContactDialog()) }
    }

    override fun onCreateAdapter() =
        ListAdapter(this, R.layout.contact_list, ::ContactModel, ::ContactDialog)
}


class ContactModel(wallet: PyObject, val contact: PyObject) : ListItemModel(wallet) {
    val name by lazy {
        contact.get("name").toString()
    }
    val addr by lazy {
        makeAddress(contact.get("address").toString())
    }
    val addrUiString by lazy {
        addr.callAttr("to_ui_string").toString()
    }
    override val dialogArguments by lazy {
        Bundle().apply {
            putString("name", name)
            putString("address", addrUiString)
        }
    }
}


class ContactDialog : DetailDialog() {
    val existingContact by lazy {
        if (arguments == null) null
        else ContactModel(wallet, makeContact(arguments!!.getString("name")!!,
                                              arguments!!.getString("address")!!))
    }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        with (builder) {
            setView(R.layout.contact_detail)
            setNegativeButton(android.R.string.cancel, null)
            setPositiveButton(android.R.string.ok, null)
            setNeutralButton(if (existingContact == null) R.string.qr_code
                             else R.string.delete,
                             null)
        }
    }

    override fun onShowDialog() {
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener { onOK() }

        val contact = existingContact
        if (contact == null) {
            for (btn in listOf(btnExplore, btnSend)) {
                (btn as View).visibility = View.INVISIBLE
            }
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { scanQR(this) }
        } else {
            btnExplore.setOnClickListener {
                exploreAddress(activity!!, contact.addr)
            }
            btnSend.setOnClickListener {
                try {
                    showDialog(activity!!, SendDialog().apply {
                        arguments = Bundle().apply {
                            putString("address", contact.addrUiString)
                        }
                    })
                    dismiss()
                } catch (e: ToastException) { e.show() }
            }
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
                showDialog(this, ContactDeleteDialog().apply {
                    arguments = contact.dialogArguments
                })
            }
        }
    }

    override fun onFirstShowDialog() {
        val contact = existingContact
        if (contact != null) {
            etName.setText(contact.name)
            etAddress.setText(contact.addrUiString)
        } else {
            etName.requestFocus()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null && result.contents != null) {
            etAddress.setText(result.contents)
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    fun onOK() {
        val name = etName.text.toString()
        val address = etAddress.text.toString()
        try {
            if (name.isEmpty()) {
                throw ToastException(R.string.name_is, Toast.LENGTH_SHORT)
            }
            makeAddress(address)  // Throws ToastException if invalid.
            val contacts = wallet.get("contacts")!!
            contacts.callAttr("add", makeContact(name, address), existingContact?.contact,
                               Kwarg("save", false))
            saveContacts(wallet, contacts)
            dismiss()
        } catch (e: ToastException) { e.show() }
    }
}


class ContactDeleteDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        val contactDialog = targetFragment as ContactDialog
        val wallet = contactDialog.wallet
        builder.setTitle(R.string.confirm_delete)
            .setMessage(R.string.are_you_sure_you_wish_to_delete)
            .setPositiveButton(R.string.delete) { _, _ ->
                val contacts = wallet.get("contacts")!!
                contacts.callAttr("remove", makeContact(arguments!!.getString("name")!!,
                                                        arguments!!.getString("address")!!),
                                  Kwarg("save", false))
                saveContacts(wallet, contacts)
                contactDialog.dismiss()
            }
            .setNegativeButton(android.R.string.cancel, null)
    }
}


fun makeContact(name: String, addr: String) =
    libContacts.callAttr("Contact", name, makeAddress(addr).callAttr("to_storage_string"),
                         "address")!!


fun saveContacts(wallet: PyObject, contacts: PyObject) {
    saveWallet(wallet) { contacts.callAttr("save") }
    daemonUpdate.setValue(Unit)
}