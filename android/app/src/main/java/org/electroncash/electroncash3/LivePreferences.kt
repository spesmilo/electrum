package org.electroncash.electroncash3

import androidx.lifecycle.MutableLiveData
import android.content.SharedPreferences


class LivePreferences(val sp: SharedPreferences, listen: Boolean = true)
    : SharedPreferences.OnSharedPreferenceChangeListener {
    private val booleans = HashMap<String, LivePreference<Boolean>>()
    private val strings = HashMap<String, LivePreference<String>>()

    init {
        if (listen) {
            sp.registerOnSharedPreferenceChangeListener(this)
        }
    }

    fun getBoolean(key: String) =
        get(booleans, key, { LiveBooleanPreference(sp, key) })

    fun getString(key: String) =
        get(strings, key, { LiveStringPreference(sp, key) })

    private fun <T> get(map: MutableMap<String, T>, key: String, create: () -> T): T {
        var result = map.get(key)
        if (result != null) {
            return result
        } else {
            result = create()
            map.put(key, result)
            return result
        }
    }

    override fun onSharedPreferenceChanged(sp: SharedPreferences, key: String) {
        booleans.get(key)?.setFromPreferences()
        strings.get(key)?.setFromPreferences()
    }
}


abstract class LivePreference<T>(val sp: SharedPreferences, val key: String)
    : MutableLiveData<T>() {

    abstract fun spGet(): T
    abstract fun spSet(value: T)

    init {
        setFromPreferences()
    }

    override fun setValue(value: T) {
        spSet(value)
    }

    fun setFromPreferences() {
        super.setValue(if (sp.contains(key)) spGet() else null)
    }
}


class LiveBooleanPreference(sp: SharedPreferences, key: String) : LivePreference<Boolean>(sp, key) {
    override fun spGet(): Boolean { return sp.getBoolean(key, false) }
    override fun spSet(value: Boolean) { sp.edit().putBoolean(key, value).apply() }
}

class LiveStringPreference(sp: SharedPreferences, key: String) : LivePreference<String>(sp, key) {
    override fun spGet(): String { return sp.getString(key, null)!! }
    override fun spSet(value: String) { sp.edit().putString(key, value).apply() }
}