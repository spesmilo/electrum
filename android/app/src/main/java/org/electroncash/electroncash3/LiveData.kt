package org.electroncash.electroncash3

import android.os.SystemClock
import androidx.lifecycle.LiveData
import androidx.lifecycle.MediatorLiveData
import androidx.lifecycle.Observer


/** Notifies observers whenever any of its sources change. */
class TriggerLiveData : MediatorLiveData<Unit>() {

    // When we become active, we only want to call each observer once, no matter how many
    // sources we have. This could be achieved using postValue , but some observers need to be
    // called synchronously. For example, postponing the setup of a RecyclerView adapter would
    // cause the view to lose its scroll position on rotation.
    enum class State {
        NORMAL, ACTIVATING, ACTIVATING_NOTIFIED
    }
    private var state = State.NORMAL

    fun addSource(source: LiveData<*>) {
        super.addSource(source) {
            if (state != State.ACTIVATING_NOTIFIED) {
                setValue(Unit)
                if (state == State.ACTIVATING) {
                    state = State.ACTIVATING_NOTIFIED
                }
            }
        }
    }

    override fun <S> addSource(source: LiveData<S>, onChanged: Observer<in S>) {
        throw IllegalArgumentException("Use the 1-argument version of this method")
    }

    override fun onActive() {
        state = State.ACTIVATING
        super.onActive()
        state = State.NORMAL
    }
}


/** Generates data by running the given function on a background thread, but only when the
 * LiveData has active observers. */
class BackgroundLiveData<T> : MediatorLiveData<T>() {

    lateinit var function: () -> T

    /** Minimum time in ms between the end of one refresh and the start of the next. */
    var minInterval: Long = 0

    private var needRefresh = false
    private var thread: Thread? = null
    private var lastRefreshTime: Long = 0

    /** Schedules a refresh. If a refresh is already in progress, another one will be started
     * once it completes. */
    fun refresh() {
        runOnUiThread {
            needRefresh = true
            if (hasActiveObservers()) {
                refreshNow()
            }
        }
    }

    override fun onActive() {
        super.onActive()
        if (needRefresh) {
            refreshNow()
        }
    }

    private fun refreshNow() {
        if (thread != null) return

        needRefresh = false
        thread = Thread {
            val sleepTime = (lastRefreshTime + minInterval) - SystemClock.uptimeMillis()
            if (sleepTime > 0) {
                SystemClock.sleep(sleepTime)
            }
            val result = function()
            lastRefreshTime = SystemClock.uptimeMillis()

            runOnUiThread {
                setValue(result)
                thread = null
                if (needRefresh && hasActiveObservers()) {
                    refreshNow()
                }
            }
        }.apply { start() }
    }
}