package org.electroncash.electroncash3

import android.arch.lifecycle.MutableLiveData
import android.arch.lifecycle.Observer
import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.support.v4.app.DialogFragment
import android.support.v7.preference.EditTextPreference
import android.support.v7.preference.ListPreference
import android.support.v7.preference.Preference
import android.support.v7.preference.PreferenceFragmentCompat
import android.support.v7.preference.PreferenceGroup
import android.support.v7.preference.PreferenceManager
import com.chaquo.python.PyObject


lateinit var settings: LivePreferences


fun initSettings() {
    val sp = PreferenceManager.getDefaultSharedPreferences(app)
    settings = LivePreferences(sp)

    // Network
    setDefaultValue(sp, "auto_connect",
                    libNetwork.get("DEFAULT_AUTO_CONNECT")!!.toBoolean())
    // null would cause issues with the preference framework, but the empty string has
    // the same effect of making the daemon choose a random server.
    setDefaultValue(sp, "server", "")

    // Appearance
    setDefaultValue(sp, "block_explorer", libWeb.get("DEFAULT_EXPLORER")!!.toString())

    // Fiat
    setDefaultValue(sp, "use_exchange_rate",
                    libExchange.get("DEFAULT_ENABLED")!!.toBoolean())
    setDefaultValue(sp, "currency", libExchange.get("DEFAULT_CURRENCY")!!.toString())
    setDefaultValue(sp, "use_exchange", libExchange.get("DEFAULT_EXCHANGE")!!.toString())

    // Set any remaining defaults from XML. Despite what some documentation says, this will NOT
    // overwrite existing values.
    PreferenceManager.setDefaultValues(app, R.xml.settings, true)
}


fun setDefaultValue(sp: SharedPreferences, key: String, default: Boolean) {
    if (!sp.contains(key)) sp.edit().putBoolean(key, default).apply()
}

fun setDefaultValue(sp: SharedPreferences, key: String, default: String) {
    if (!sp.contains(key)) sp.edit().putString(key, default).apply()
}


class SettingsFragment : PreferenceFragmentCompat(), MainFragment {
    override val title = MutableLiveData<String>().apply {
        value = app.getString(R.string.settings)
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.settings, rootKey)

        // Appearance
        setEntries("block_explorer", libWeb.callAttr("BE_sorted_list"))

        // Fiat
        val currencies = libExchange.callAttr("get_exchanges_by_ccy", false)
        setEntries("currency", py.builtins.callAttr("sorted", currencies))
        settings.getString("currency").observe(this, Observer { currency ->
            val prefExchange = findPreference("use_exchange") as ListPreference
            setEntries("use_exchange",
                       py.builtins.callAttr("sorted", currencies.callAttr("get", currency)))
            if (prefExchange.value !in prefExchange.entries) {
                prefExchange.value = prefExchange.entries[0].toString()
            }
        })

        // Do last, otherwise exchanges entries won't be populated yet and summary won't appear.
        observeGroup(preferenceScreen)
    }

    fun setEntries(key: String, pyList: PyObject) {
        val arr = pyList.asList().map { it.toString() }.toTypedArray()
        (findPreference(key) as ListPreference).apply {
            entries = arr
            entryValues = arr
        }
    }

    fun observeGroup(group: PreferenceGroup) {
        for (i in 0 until group.preferenceCount) {
            val pref = group.getPreference(i)
            if (pref is PreferenceGroup) {
                observeGroup(pref)
            } else if (pref is EditTextPreference) {
                settings.getString(pref.key).observe(this, Observer {
                    pref.text = it
                    pref.summary = pref.text
                })
            } else if (pref is ListPreference) {
                settings.getString(pref.key).observe(this, Observer {
                    pref.value = it
                    pref.summary = pref.entry
                })
            }
        }
    }

    override fun onPreferenceTreeClick(preference: Preference): Boolean {
        if (preference.key == "console") {
            startActivity(Intent(activity!!, ECConsoleActivity::class.java))
            return true
        } else {
            return super.onPreferenceTreeClick(preference)
        }
    }

    override fun onDisplayPreferenceDialog(preference: Preference) {
        var dialog: DialogFragment? = null
        if (preference is ServerPreference) {
            dialog = ServerPreferenceDialog()
        }

        if (dialog != null) {
            dialog.arguments = Bundle().apply { putString("key", preference.key) }
            dialog.setTargetFragment(this, 0)
            showDialog(activity!!, dialog)
        } else {
            super.onDisplayPreferenceDialog(preference)
        }
    }
}

