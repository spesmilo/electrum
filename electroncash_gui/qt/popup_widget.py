#
# PopupWidget and PopupLabel
# by Calin Culianu <calin.culianu@gmail.com>
#
# Adapted from my C++ sourcecode used in the VikingRecorder project.
#
# LICENSE: MIT
#
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
import sys

class PopupWidget(QWidget):

    #   enum PointerPosition
    LeftSide = 0; RightSide = 1;  TopSide = 2; BottomSide = 3; NoPointer = 4

    LR_MARGIN = 10.0#8.0 #/* left / right margin  */
    TB_MARGIN = 8.0#5.5 #/* top / bottom margin */

    didHide = pyqtSignal()
    didShow = pyqtSignal()
    onClick = pyqtSignal()
    onRightClick = pyqtSignal()

    def __init__(self, parent = None, timeout = None, delete_on_hide = True,
                 activation_hides = True, dark_mode = False):
        ''' parent should be a window or None
            timeout is the amount of time, in milliseconds, to show the widget before it is auto-hidden. None is no timeout.
            delete_on_hide, if True, will auto-delete this widget after it is hidden due to the timeout or due to calling hide().
        '''
        super().__init__(parent)
        self.layout = QGridLayout(self)
        if sys.platform != 'darwin':
            self.layout.setContentsMargins(20,20,20,20)
        self.animation = QPropertyAnimation(self)
        self.final_opacity = 1.0
        self.popup_opacity = 1.0
        self.pointerPos = self.LeftSide
        self._timer = None
        self.activation_hides = activation_hides
        self.dark_mode = dark_mode

        #self.resize(200, 50)

        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)

        self.animation.setTargetObject(self)
        self.animation.setPropertyName(b'popupOpacity')
        self.animation.setDuration(200)

        self.setLayout(self.layout)

        if parent: parent.installEventFilter(self)

        self.timeout = timeout
        self.delete_on_hide = delete_on_hide


    def getPointerPosition(self): return self.pointerPos
    def setPointerPosition(self, r): self.pointerPos = r; self.update()

    @pyqtProperty(float) # Property so that Qt animations work. You may set the actual attrbute directly and ingore this in client code
    def popupOpacity(self): return self.popup_opacity
    @popupOpacity.setter
    def popupOpacity(self, value):
        self.popup_opacity = value
        self.setWindowOpacity(value)
    @pyqtProperty(float) # Property so that Qt animations work. You may set the actual attrbute directly and ingore this in client code
    def finalOpacity(self): return self.final_opacity
    @finalOpacity.setter
    def finalOpacity(self, value): self.final_opacity = value

    def paintEvent(self, e):
        #// Draw the popup here
        #// You can always pick an image and use drawPixmap to
        #// draw it in order to make things simpler

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setClipRegion(e.region())
        painter.fillRect(e.rect(),QColor(0,0,0,0))

        #// Prepare the popup dimensions
        roundedRectDimensions = QRectF()
        roundedRectDimensions.setX(self.rect().x() + self.LR_MARGIN)
        roundedRectDimensions.setY(self.rect().y() + self.TB_MARGIN)
        roundedRectDimensions.setWidth(self.rect().width() - self.LR_MARGIN*2.0)
        roundedRectDimensions.setHeight(self.rect().height() - self.TB_MARGIN*2.0)

        pal = QPalette(self.palette())

        painter.setBrush(QBrush(pal.color(QPalette.Window if self.dark_mode else QPalette.Mid)))


        pen = QPen()
        pen.setColor(pal.color(QPalette.Light if self.dark_mode else QPalette.Button))
        pen.setWidth(3)
        painter.setPen(pen)

        #// Draw the popup body
        painter.drawRoundedRect(roundedRectDimensions, self.LR_MARGIN*2.0, self.TB_MARGIN*2.0)

        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(pal.color(QPalette.BrightText if self.dark_mode else QPalette.Dark)))
        #// Draw the popup pointer based on relPos
        self.drawPopupPointer(painter)

        e.accept()

    def drawPopupPointer(self, p):
        r = QRectF(self.rect())

        if self.pointerPos == self.LeftSide:
            PPIX_X = self.LR_MARGIN; PPIX_Y = PPIX_X*2.0
            points = [
                QPointF(QPoint(r.x()+PPIX_X, r.height()/2.0 - PPIX_Y/2.0)),
                QPointF(QPoint(r.x()+PPIX_X, r.height()/2.0 + PPIX_Y/2.0)),
                QPointF(QPoint(r.x(), r.height() / 2.0))
            ]

            p.drawPolygon(*points)

        if self.pointerPos == self.RightSide:
            PPIX_X = self.LR_MARGIN; PPIX_Y = PPIX_X*2.0
            points = [
                QPointF(QPoint(r.right()-PPIX_X, r.height()/2.0 - PPIX_Y/2.0)),
                QPointF(QPoint(r.right()-PPIX_X, r.height()/2.0 + PPIX_Y/2.0)),
                QPointF(QPoint(r.right(), r.height() / 2.0))
            ]

            p.drawPolygon(*points)

        if self.pointerPos == self.TopSide:
            PPIX_Y = self.TB_MARGIN; PPIX_X = PPIX_Y*2.0
            points = [
                QPointF(QPoint(r.x()+r.width()/2.0 - PPIX_X/2.0, r.top() + PPIX_Y)),
                QPointF(QPoint(r.x()+r.width()/2.0 + PPIX_X/2.0, r.top() + PPIX_Y)),
                QPointF(QPoint(r.x()+r.width()/2.0, r.top()))
            ]

            p.drawPolygon(*points)

        if self.pointerPos == self.BottomSide:
            PPIX_Y = self.TB_MARGIN; PPIX_X = PPIX_Y*2.0
            points = [
                QPointF(QPoint(r.x()+r.width()/2.0 - PPIX_X/2.0, r.bottom() - PPIX_Y)),
                QPointF(QPoint(r.x()+r.width()/2.0 + PPIX_X/2.0, r.bottom() - PPIX_Y)),
                QPointF(QPoint(r.x()+r.width()/2.0, r.bottom()))
            ]

            p.drawPolygon(*points)

    def showRelativeTo(self, w):
        s = self.size()
        self.moveRelativeTo(w)
        self.hide()
        self.show()
        if self.pointerPos == self.NoPointer:
            self.raise_()
        if s != self.size():
            # show caused widget resize.. recenter
            self.moveRelativeTo(w)


    def moveRelativeTo(self, w):
        if not w:
            print("INTERNAL ERROR: PopupWidget::showRelativeTo got passed a NULL widget pointer! Ignoring.. FIXME!")
            return

        p = w.mapToGlobal(QPoint(0,0))
        if self.pointerPos == self.LeftSide:
            p.setX(p.x()+w.width())
            p.setY(p.y()-self.height()//2+w.height()//2)
        elif self.pointerPos == self.RightSide:
            p.setX(p.x()-self.width())
            p.setY(p.y()-self.height()//2+w.height()//2)
        elif self.pointerPos == self.BottomSide:
            p.setX(p.x()+w.width()//2 - self.width()//2)
            p.setY(p.y()-self.height())
        elif self.pointerPos == self.TopSide:
            p.setX(p.x()+w.width()//2 - self.width()//2)
            p.setY(p.y()+w.height())
        else:
            #// just center it on the widget
            p.setX(p.x()+w.width()//2 - self.width()//2)
            p.setY(p.y()+w.height()//2 - self.height()//2)
            if self.isVisible():
                self.raise_()

        self.move(p);

    def _killTimer(self):
        if self._timer:
            self._timer.stop()
            self._timer.deleteLater()
            self._timer = None

    def _startTimer(self, target):
        self._killTimer()
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        def timeout():
            self._killTimer()
            target()
        self._timer.timeout.connect(timeout)
        self._timer.start(int(self.timeout))

    def showEvent(self, e):
        super().showEvent(e)
        if not e.isAccepted():
            return
        if self.animation.state() == QAbstractAnimation.Running:
            return
        self.setWindowOpacity(0.0)

        self.animation.setStartValue(0.0)
        self.animation.setEndValue(self.final_opacity)

        self.didShow.emit()
        self._cleanUp()
        self.animation.setDirection(QAbstractAnimation.Forward)
        self.animation.start()

        if isinstance(self.timeout, (float, int)) and self.timeout > 0:
            def autoHide():
                self._cleanUp()
                self._startTimer(self.hideAnimated)
            self.animation.finished.connect(autoHide)

    def hideEvent(self, e):
        super().hideEvent(e)
        if e.isAccepted():
            self._cleanUp()
            if self.delete_on_hide:
                self.setParent(None)
                self.deleteLater()

    def _disconnectFinished(self):
            try: self.animation.finished.disconnect()
            except: pass

    def hideAnimated(self):
        if self.animation.state() == QAbstractAnimation.Running:
            return
        self._cleanUp()
        self.animation.setDirection(QAbstractAnimation.Backward)
        self.animation.start()
        def doHide():
            self._cleanUp()
            self.hide()
            self.didHide.emit()
        self.animation.finished.connect(doHide)

    def eventFilter(self, obj, e):
        evts = (QEvent.Move, QEvent.Resize, QEvent.Close, QEvent.Hide, QEvent.Show)
        if self.activation_hides:
            evts = (*evts, QEvent.WindowStateChange, QEvent.WindowDeactivate)
        if e.type() in evts:
            # if the parent window is moved or otherwise touched, make this popup go away
            self.hideAnimated()
        return False

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self.onClick.emit()
            e.accept()
        elif e.button() == Qt.RightButton:
            self.onRightClick.emit()
            e.accept()

    def _cleanUp(self):
        ''' Forces animation and timer to stop. This is essential to force
        the object into a known consistent state ready for deletion, restart
        of animations, etc. '''
        self._disconnectFinished()
        self._killTimer()
        self.animation.stop()


class PopupLabel(PopupWidget):

    def __init__(self, text = "", parent = None, alignment = None, textColor = None, **kwargs):
        super().__init__(parent, **kwargs)
        self.label = QLabel(text, self)
        if alignment is None:
            alignment = Qt.AlignCenter
        self.label.setAlignment(alignment)
        self.label.setWordWrap(True)
        self.label.setScaledContents(True)
        p = QPalette(self.label.palette())
        p.setColor(QPalette.Window,QColor(0,0,0,0))
        if textColor is None:
            textColor = QColor(255,255,255,255) if not self.dark_mode else p.color(QPalette.BrightText)
        p.setColor(QPalette.WindowText,textColor)
        self.label.setPalette(p);

        self.layout.addWidget(self.label, 0, 0);

        self.setAutoFillBackground(False)
        self.setUpdatesEnabled(True)

    def setPopupText(self, text):
        self.label.setText(text)

### Helpers for EC integration
from .util import destroyed_print_error
from electroncash.util import finalization_print_error

_extant_popups = dict()
def ShowPopupLabel(text, target, timeout, name="Global", pointer_position=PopupWidget.RightSide, opacity=0.9, onClick=None, onRightClick=None,
                   activation_hides=True, track_target=True, dark_mode=False):
    assert isinstance(name, str) and isinstance(text, str) and isinstance(target, QWidget) and isinstance(timeout, (float, int)), "Invalid parameters"
    window = target.window()
    if not window.isActiveWindow():
        return False
    KillPopupLabel(name)
    popup = PopupLabel(text, window, timeout=timeout, delete_on_hide=True, activation_hides=activation_hides, dark_mode=dark_mode)
    popup.setPointerPosition(pointer_position)
    popup.final_opacity = opacity
    popup.setObjectName(str(id(popup)))
    def onDestroyed(x):
        # NB: even though x and popup are the same object, they will have different id() at this point (I think this is because Qt destructed the python object stub and is passing us a reference to the QWidget base here.)
        xid = None
        try:
            xid = int(x.objectName())
        except (ValueError,TypeError):
            pass
        if xid == id(_extant_popups.get(name, None)):
            # Clean up the dict entry
            _extant_popups.pop(name, None)
            #print("----> Destroyed and cleaned up:",name)
        else:
            # Stale object or already removed from dict. No need to clean up the dict entry
            pass
            #print("----> Not found!!")
    if track_target:
        class MyEventFilter(QObject):
            ''' Traps target move events and moves the popup to line up with the target '''
            def eventFilter(self, obj, e):
                lbl = self.parent()
                if e.type() in (QEvent.Move, QEvent.Resize) and isinstance(lbl, PopupLabel):
                    # track the target, moving us along with it if its geometry changes
                    lbl.moveRelativeTo(obj)
                return False
        popup.my_e_filter = MyEventFilter(popup)
        target.installEventFilter(popup.my_e_filter)
    popup.destroyed.connect(onDestroyed)
    destroyed_print_error(popup, "[PopupLabel/{}] destroyed".format(name))
    finalization_print_error(popup, "[PopupLabel/{}] finalized".format(name))
    _extant_popups[name] = popup
    if onClick:
        popup.onClick.connect(onClick, Qt.QueuedConnection)
    if onRightClick:
        popup.onRightClick.connect(onRightClick, Qt.QueuedConnection)
    popup.showRelativeTo(target)
    return True

def KillPopupLabel(name="Global"):
    extant = _extant_popups.pop(name, None)
    if extant:
        try: extant.destroyed.disconnect()
        except: pass
        try:
            destroyed_print_error(extant, "[PopupLabel/{}] destroyed".format(name))
            extant._cleanUp()
            extant.setParent(None)
            extant.deleteLater()
        except RuntimeError:
            ''' In rare cases, wrapped C++ object may be dead already; see #1796 '''
        #print("----> Found and killed extant label")
