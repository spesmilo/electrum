import queue
import sys
from typing import Optional, NamedTuple, Callable
import os.path

from PyQt6 import QtGui
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QPen, QPaintDevice, QFontDatabase, QImage
import qrcode

from electrum.i18n import _
from electrum.logging import Logger

_cached_font_ids: dict[str, int] = {}


def get_font_id(filename: str) -> int:
    font_id = _cached_font_ids.get(filename)
    if font_id is not None:
        return font_id
    # font_id will be negative on error
    font_id = QFontDatabase.addApplicationFont(
        os.path.join(os.path.dirname(__file__), '..', 'fonts', filename)
    )
    _cached_font_ids[filename] = font_id
    return font_id


def draw_qr(
    *,
    qr: Optional[qrcode.main.QRCode],
    paint_device: QPaintDevice,  # target to paint on
    is_enabled: bool = True,
    min_boxsize: int = 2,  # min size in pixels of single black/white unit box of the qr code
) -> None:
    """Draw 'qr' onto 'paint_device'.
    - qr.box_size is ignored. We will calculate our own boxsize to fill the whole size of paint_device.
    - qr.border is respected.
    """
    black = QColor(0, 0, 0, 255)
    grey = QColor(196, 196, 196, 255)
    white = QColor(255, 255, 255, 255)
    black_pen = QPen(black) if is_enabled else QPen(grey)
    black_pen.setJoinStyle(Qt.PenJoinStyle.MiterJoin)

    if not qr:
        qp = QtGui.QPainter()
        qp.begin(paint_device)
        qp.setBrush(white)
        qp.setPen(white)
        r = qp.viewport()
        qp.drawRect(0, 0, r.width(), r.height())
        qp.end()
        return

    # note: next line can raise qrcode.exceptions.DataOverflowError (or ValueError)
    matrix = qr.get_matrix()  # includes qr.border
    k = len(matrix)
    qp = QtGui.QPainter()
    qp.begin(paint_device)
    r = qp.viewport()
    framesize = min(r.width(), r.height())
    boxsize = int(framesize / k)
    if boxsize < min_boxsize:
        # The amount of data is still within what can fit into a QR code,
        # however we don't have enough pixels to draw it.
        qp.setBrush(white)
        qp.setPen(white)
        qp.drawRect(0, 0, r.width(), r.height())
        qp.setBrush(black)
        qp.setPen(black)
        qp.drawText(0, 20, _("Cannot draw QR code") + ":")
        qp.drawText(0, 40, _("Not enough space available."))
        qp.end()
        return
    size = k * boxsize
    left = (framesize - size) / 2
    top = (framesize - size) / 2
    # Draw white background with margin
    qp.setBrush(white)
    qp.setPen(white)
    qp.drawRect(0, 0, framesize, framesize)
    # Draw qr code
    qp.setBrush(black if is_enabled else grey)
    qp.setPen(black_pen)
    for r in range(k):
        for c in range(k):
            if matrix[r][c]:
                qp.drawRect(
                    int(left + c * boxsize), int(top + r * boxsize),
                    boxsize - 1, boxsize - 1)
    qp.end()


def paintQR(data) -> Optional[QImage]:
    if not data:
        return None

    # Create QR code
    qr = qrcode.QRCode()
    qr.add_data(data)

    # Create a QImage to draw on
    matrix = qr.get_matrix()
    k = len(matrix)
    boxsize = 5
    size = k * boxsize

    # Create the image with appropriate size
    base_img = QImage(size, size, QImage.Format.Format_ARGB32)

    # Use draw_qr to paint on the image
    draw_qr(
        qr=qr,
        paint_device=base_img,
        is_enabled=True,
        min_boxsize=boxsize
    )

    return base_img


class TaskThread(QThread, Logger):
    """Thread that runs background tasks.  Callbacks are guaranteed
    to happen in the context of its parent."""

    class Task(NamedTuple):
        task: Callable
        cb_success: Optional[Callable]
        cb_done: Optional[Callable]
        cb_error: Optional[Callable]
        cancel: Optional[Callable] = None

    doneSig = pyqtSignal(object, object, object)

    def __init__(self, parent, on_error=None):
        QThread.__init__(self, parent)
        Logger.__init__(self)
        self.on_error = on_error
        self.tasks = queue.Queue()
        self._cur_task = None  # type: Optional[TaskThread.Task]
        self._stopping = False
        self.doneSig.connect(self.on_done)
        self.start()

    def add(self, task, on_success=None, on_done=None, on_error=None, *, cancel=None):
        if self._stopping:
            self.logger.warning(f"stopping or already stopped but tried to add new task.")
            return
        on_error = on_error or self.on_error
        task_ = TaskThread.Task(task, on_success, on_done, on_error, cancel=cancel)
        self.tasks.put(task_)

    def run(self):
        while True:
            if self._stopping:
                break
            task = self.tasks.get()  # type: TaskThread.Task
            self._cur_task = task
            if not task or self._stopping:
                break
            try:
                result = task.task()
                self.doneSig.emit(result, task.cb_done, task.cb_success)
            except BaseException:
                self.doneSig.emit(sys.exc_info(), task.cb_done, task.cb_error)

    def on_done(self, result, cb_done, cb_result):
        # This runs in the parent's thread.
        if cb_done:
            cb_done()
        if cb_result:
            cb_result(result)

    def stop(self):
        self._stopping = True
        # try to cancel currently running task now.
        # if the task does not implement "cancel", we will have to wait until it finishes.
        task = self._cur_task
        if task and task.cancel:
            task.cancel()
        # cancel the remaining tasks in the queue
        while True:
            try:
                task = self.tasks.get_nowait()
            except queue.Empty:
                break
            if task and task.cancel:
                task.cancel()
        self.tasks.put(None)  # in case the thread is still waiting on the queue
        self.exit()
        self.wait()
