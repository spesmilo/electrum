import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    title: qsTr('Loading Wallet')
    iconSource: Qt.resolvedUrl('../../icons/wallet.png')

    resizeWithKeyboard: false

    x: Math.floor((parent.width - implicitWidth) / 2)
    y: Math.floor((parent.height - implicitHeight) / 2)
    // anchors.centerIn: parent // this strangely pixelates the spinner
    needsSystemBarPadding: false

    function open() {
        showTimer.start()
    }

    ColumnLayout {
        width: parent.width

        BusyIndicator {
            Layout.alignment: Qt.AlignHCenter

            running: Daemon.loading
        }

        Item {
            Layout.preferredHeight: 20
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
