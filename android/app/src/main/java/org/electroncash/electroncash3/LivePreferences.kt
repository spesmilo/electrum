package org.electroncash.electroncash3

import android.annotation.SuppressLint
import android.content.SharedPreferences
import androidx.lifecycle.MutableLiveData
import java.lang.ArithmeticException


class LivePreferences(val sp: SharedPreferences, listen: Boolean = true)
    : SharedPreferences.OnSharedPreferenceChangeListener {

    private val prefs = HashMap<String, LivePreference<*>>()
    private val booleans = HashMap<String, LivePreference<Boolean>>()
    private val strings = HashMap<String, LivePreference<String>>()
    private val ints = HashMap<String, LivePreference<Int>>()

    init {
        if (listen) {
            sp.registerOnSharedPreferenceChangeListener(this)
        }
    }

    fun getBoolean(key: String) =
        get(booleans, key, { LiveBooleanPreference(sp, key) })

    fun getInt(key: String) =
        get(ints, key, { LiveIntPreference(sp, key) })

    fun getString(key: String) =
        get(strings, key, { LiveStringPreference(sp, key) })

    private fun <T: LivePreference<*>> get(map: MutableMap<String, T>, key: String,
                                           create: () -> T): T {
        var result = map.get(key)
        if (result != null) {
            return result
        } else {
            result = create()
            map.put(key, result)
            prefs.put(key, result)
            return result
        }
    }

    override fun onSharedPreferenceChanged(sp: SharedPreferences, key: String) {
        prefs.get(key)?.setFromPreferences()
    }
}


abstract class LivePreference<T>(val sp: SharedPreferences, val key: String)
    : MutableLiveData<T>() {

    @SuppressLint("CommitPrefEdits")
    val spe = sp.edit()!!

    abstract fun spGet(): T
    abstract fun spSet(value: T)

    init {
        setFromPreferences()
    }

    override fun setValue(value: T) {
        spSet(value)
        spe.apply()  // Triggers listener, which calls setFromPreferences.
    }

    fun setFromPreferences() {
        super.setValue(if (sp.contains(key)) spGet() else null)
    }
}


class LiveBooleanPreference(sp: SharedPreferences, key: String) : LivePreference<Boolean>(sp, key) {
    override fun spGet(): Boolean { return sp.getBoolean(key, false) }
    override fun spSet(value: Boolean) { spe.putBoolean(key, value) }
}

class LiveIntPreference(sp: SharedPreferences, key: String) : LivePreference<Int>(sp, key) {
    override fun spGet(): Int {
        try {
            return sp.getInt(key, 0)
        } catch (e: ClassCastException) {
            // We used to use long, but we now use int for easier interaction with Java APIs.
            val resultLong = sp.getLong(key, 0)
            val resultInt = resultLong.toInt()
            if (resultLong != resultInt.toLong()) {
                throw ArithmeticException("$resultLong is too large to convert to int")
            }
            return resultInt
        }
    }

    override fun spSet(value: Int) { spe.putInt(key, value) }
}

class LiveStringPreference(sp: SharedPreferences, key: String) : LivePreference<String>(sp, key) {
    override fun spGet(): String { return sp.getString(key, null)!! }
    override fun spSet(value: String) { spe.putString(key, value) }
}