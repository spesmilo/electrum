import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

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

    ColumnLayout {
        width: parent.width

        BusyIndicator {
            Layout.alignment: Qt.AlignHCenter

            running: Daemon.loading
        }
    }

    Connections {
        target: Daemon
        function onLoadingChanged() {
            if (!Daemon.loading)
                dialog.close()
        }
    }
}
