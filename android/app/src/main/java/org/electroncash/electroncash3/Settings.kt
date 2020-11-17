package org.electroncash.electroncash3

import android.content.SharedPreferences
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.DialogFragment
import androidx.lifecycle.observe
import androidx.preference.EditTextPreference
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.PreferenceGroup
import androidx.preference.PreferenceManager
import com.chaquo.python.PyObject


lateinit var settings: LivePreferences


fun initSettings() {
    val sp = PreferenceManager.getDefaultSharedPreferences(app)
    settings = LivePreferences(sp)
    setDefaultValues(sp)

    settings.getBoolean("cashaddr_format").observeForever {
        clsAddress.callAttr("show_cashaddr", it)
    }
    settings.getString("base_unit").observeForever {
        unitName = it!!
        val places = libUtil.get("base_units")!!.callAttr("get", it)
        if (places != null) {
            unitPlaces = places.toInt()
        } else {
            // The chosen unit has been renamed or removed: revert to the default.
            settings.getString("base_unit").setValue(
                libUtil.get("DEFAULT_BASE_UNIT")!!.toString())
        }
    }
}


fun setDefaultValues(sp: SharedPreferences) {
    // Network
    setDefaultValue(sp, "auto_connect",
                    libNetwork.get("DEFAULT_AUTO_CONNECT")!!.toBoolean())
    // null would cause issues with the preference framework, but the empty string has
    // the same effect of making the daemon choose a random server.
    setDefaultValue(sp, "server", "")

    // Transactions
    setDefaultValue(sp, "confirmed_only",
                    libWallet.get("DEFAULT_CONFIRMED_ONLY")!!.toBoolean())

    // Appearance
    setDefaultValue(sp, "cashaddr_format",
                    clsAddress.get("FMT_UI") == clsAddress.get("FMT_CASHADDR"))
    setDefaultValue(sp, "base_unit", libUtil.get("DEFAULT_BASE_UNIT")!!.toString())
    setDefaultValue(sp, "block_explorer", libWeb.callAttr("BE_default_explorer")!!.toString())

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


class SettingsActivity : AppCompatActivity(R.layout.settings)

class SettingsFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.settings, rootKey)

        // Appearance
        setEntries("base_unit", libUtil.get("base_units")!!)
        setEntries("block_explorer", libWeb.callAttr("BE_sorted_list"))

        // Fiat
        val currencies = libExchange.callAttr("get_exchanges_by_ccy", false)
        setEntries("currency", py.builtins.callAttr("sorted", currencies))
        settings.getString("currency").observe(this, { currency ->
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

    fun setEntries(key: String, pySequence: PyObject) {
        val arr = pySequence.toJava(Array<String>::class.java)
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
                settings.getString(pref.key).observe(this, {
                    pref.text = it
                    pref.summary = pref.text
                })
            } else if (pref is ListPreference) {
                settings.getString(pref.key).observe(this, {
                    pref.value = it
                    pref.summary = pref.entry
                })
            }
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

