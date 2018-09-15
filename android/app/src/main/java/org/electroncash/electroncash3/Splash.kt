package org.electroncash.electroncash3

import android.arch.lifecycle.MutableLiveData
import android.arch.lifecycle.Observer
import android.arch.lifecycle.ViewModel
import android.arch.lifecycle.ViewModelProviders
import android.content.Intent
import android.os.Bundle
import android.support.v7.app.AppCompatActivity


class SplashActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.splash)

        val model = ViewModelProviders.of(this).get(SplashModel::class.java)
        model.ready.observe(this, Observer {
            startActivity(Intent(this, MainActivity::class.java))
            finish()
        })
    }
}

class SplashModel : ViewModel() {
    val thread = Thread {
        // Start Python and load electroncash module: this may take several seconds.
        libMod.id()
        ready.postValue(Unit)
    }

    val ready = MutableLiveData<Unit>()

    init {
        thread.start()
    }
}