from typing import Optional

from PyQt6 import QtGui
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPen, QPaintDevice
import qrcode

from electrum.i18n import _


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

