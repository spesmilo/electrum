import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// "Loading Wallet" of the Material 3 GUI (app.loadingWalletDialog, created by main.qml onLoadingChanged with
// allowClose: false).
// repeats: components/LoadingWalletDialog.qml:10-63 (resizeWithKeyboard false, the position by
// Math.floor instead of anchors.centerIn (the classic comment: centerIn pixelates the spinner), the own open()
// that shows the dialog only after 250 ms, the spinner running while Daemon.loading, on Daemon.loadingChanged
// to false: stop the timer, close a visible dialog, destroy a never shown one by hand (its onClosed never comes)).
// Look: an M3Dialog of the minimum width without icon and buttons, the headline
// and the spinner centered below it.
// Strings carried over keep the translation context of LoadingWalletDialog.qml.
M3Dialog {
    id: dialog

    title: qsTranslate('LoadingWalletDialog', 'Loading Wallet')

    resizeWithKeyboard: false

    width: Math.min(312, parent.width - 2 * m3.space24)
    anchors.centerIn: undefined
    x: Math.floor((parent.width - width) / 2)
    y: Math.floor((parent.height - implicitHeight) / 2)
    // anchors.centerIn: parent // this strangely pixelates the spinner (classic)

    function open() {
        showTimer.start()
    }

    contentItem: ColumnLayout {
        spacing: 0

        BusyIndicator {
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: m3.space8
            Layout.bottomMargin: m3.space8

            running: Daemon.loading
        }
    }

    Connections {
        target: Daemon
        function onLoadingChanged() {
            console.log('daemon loading ' + Daemon.loading)
            if (!Daemon.loading) {
                showTimer.stop()
                if (dialog.visible) {
                    dialog.close()
                } else {
                    // if the dialog wasn't visible its onClosed callbacks don't get called, so it
                    // needs to be destroyed manually
                    Qt.callLater(function() { dialog.destroy() })
                }
            }
        }
    }

    Timer {
        id: showTimer
        interval: 250
        repeat: false
        onTriggered: dialog.visible = true
    }
}
