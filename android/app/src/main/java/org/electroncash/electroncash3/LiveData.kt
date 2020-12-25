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
@Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
class BackgroundLiveData<Args: Any, Result> : MediatorLiveData<Result>() {

    lateinit var function: (Args) -> Result

    /** Whether to notify observers of values which are not up to date because another refresh
     * has been scheduled. */
    var notifyIncomplete = true

    /** Minimum time in ms between the end of one refresh and the start of the next. */
    var minInterval: Long = 0

    private var nextArgs: Args? = null
    private var thread: Thread? = null
    private var lastRefreshTime: Long = 0

    @Synchronized fun isComplete() =
        nextArgs == null && thread == null

    @Synchronized fun waitUntilComplete() {
        while (!isComplete()) {
            (this as Object).wait()
        }
    }

    /** Schedules a refresh. If a refresh is already in progress, another one will be started
     * once it completes. */
    @Synchronized fun refresh(args: Args) {
        nextArgs = args
        if (hasActiveObservers()) {
            refreshNow()
        }
    }

    @Synchronized override fun onActive() {
        super.onActive()
        if (!isComplete()) {
            refreshNow()
        }
    }

    private fun refreshNow() {
        if (thread != null) return

        val args = nextArgs!!
        nextArgs = null
        thread = Thread {
            val sleepTime = (lastRefreshTime + minInterval) - SystemClock.uptimeMillis()
            if (sleepTime > 0) {
                SystemClock.sleep(sleepTime)
            }
            val result = function(args)
            lastRefreshTime = SystemClock.uptimeMillis()
            runOnUiThread { refreshDone(result) }
        }.apply { start() }
    }

    @Synchronized private fun refreshDone(result: Result) {
        if (nextArgs == null || notifyIncomplete) {
            setValue(result)
        }
        thread = null
        if (isComplete()) {
            (this as Object).notifyAll()
        } else if (hasActiveObservers()) {
            refreshNow()
        }
    }
}