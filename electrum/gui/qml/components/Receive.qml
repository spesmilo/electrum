import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Pane {
    id: rootItem
    visible: Daemon.currentWallet !== undefined

    ColumnLayout {
        width: parent.width
        spacing: 20

        Image {
            id: img
        }

        TextField {
            id: text
        }

        Button {
            text: 'generate'
            onClicked: {
                img.source = 'image://qrgen/' + text.text
            }
        }
    }

}
