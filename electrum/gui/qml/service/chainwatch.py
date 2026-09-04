# Scheduling helper for the "Chainwatch" background service.
#
# Registers a WorkManager PeriodicWorkRequest that fires ~hourly and survives
# reboot (WorkManager reschedules; no BOOT_COMPLETED receiver
# needed). The work is deferrable and inexact (batched, Doze-aware) and the minimum
# periodic interval is 15 minutes. Requires the app to have been launched at
# least once since install before it will run.
#
# Call schedule_chainwatch() once on Android during app startup for WorkManager
# registration (idempotent via ExistingPeriodicWorkPolicy.KEEP).

import os

from electrum.logging import get_logger

_logger = get_logger(__name__)

UNIQUE_WORK_NAME = "electrum-chainwatch"


def is_android():
    return 'ANDROID_DATA' in os.environ


def schedule_chainwatch():
    if not is_android():
        return
    from jnius import autoclass, cast
    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    context = PythonActivity.mActivity.getApplicationContext()

    WorkManager = autoclass('androidx.work.WorkManager')
    Builder = autoclass('androidx.work.PeriodicWorkRequest$Builder')
    TimeUnit = autoclass('java.util.concurrent.TimeUnit')
    Policy = autoclass('androidx.work.ExistingPeriodicWorkPolicy')
    JClass = autoclass('java.lang.Class')

    worker_cls = JClass.forName('org.electrum.worker.ElectrumWorker')
    request = cast('androidx.work.PeriodicWorkRequest',
                   Builder(worker_cls, 1, TimeUnit.HOURS).build())

    WorkManager.getInstance(context).enqueueUniquePeriodicWork(
        UNIQUE_WORK_NAME, Policy.KEEP, request)
    _logger.info(f'schedule_chainwatch: enqueued periodic work {UNIQUE_WORK_NAME!r}')


def cancel_chainwatch():
    if not is_android():
        return
    from jnius import autoclass
    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    context = PythonActivity.mActivity.getApplicationContext()
    WorkManager = autoclass('androidx.work.WorkManager')
    WorkManager.getInstance(context).cancelUniqueWork(UNIQUE_WORK_NAME)


def run_chainwatch_now():
    """Debug: enqueue a OneTimeWorkRequest that runs ElectrumWorker immediately.

    Unlike the periodic job, this has no timing gate, so it dispatches within
    seconds of enqueue and is observable in logcat. Useful because
    `cmd jobscheduler run` cannot force a WorkManager *periodic* job to run
    early (WorkManager just reschedules on its own next-run time).
    """
    if not is_android():
        _logger.info('run_chainwatch_now: not android, skipping')
        return

    DEBUG_WORK_TAG = "chainwatch-debug"

    from jnius import autoclass
    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    context = PythonActivity.mActivity.getApplicationContext()

    WorkManager = autoclass('androidx.work.WorkManager')
    Builder = autoclass('androidx.work.OneTimeWorkRequest$Builder')
    JClass = autoclass('java.lang.Class')

    worker_cls = JClass.forName('org.electrum.worker.ElectrumWorker')
    # Tag it so we can read back the WorkInfo state and confirm WorkManager
    # actually accepted (and is scheduling) the request.
    request = Builder(worker_cls).addTag(DEBUG_WORK_TAG).build()

    # getInstance() raises IllegalStateException if WorkManager was never
    # initialized (e.g. its startup InitializationProvider got stripped from the
    # merged manifest) - surface that clearly rather than as a generic failure.
    wm = WorkManager.getInstance(context)
    _logger.info('run_chainwatch_now: enqueueing OneTimeWorkRequest for ElectrumWorker')
    wm.enqueue(request)

    # Read back the state synchronously (ListenableFuture.get()) to prove the
    # request landed: expect ENQUEUED here, transitioning to RUNNING/SUCCEEDED.
    try:
        infos = wm.getWorkInfosByTag(DEBUG_WORK_TAG).get()
        states = [str(infos.get(i).getState()) for i in range(infos.size())]
        _logger.info(f'run_chainwatch_now: enqueued OK, WorkInfo states={states}')
    except Exception as e:
        _logger.warning(f'run_chainwatch_now: enqueued, but reading WorkInfo failed: {e!r}')
