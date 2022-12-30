import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: rootItem

    title: qsTr('Server settings')

    parent: Overlay.overlay
    modal: true
    standardButtons: Dialog.Close

    width: parent.width
    height: parent.height

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    padding: 0

    ColumnLayout {
        width: parent.width
        height: parent.height
        spacing: 0

        ServerConfig {
            id: serverconfig
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge
        }

        Item { Layout.fillHeight: true; Layout.preferredWidth: 1 }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Ok')
            icon.source: '../../icons/confirmed.png'
            onClicked: {
                Config.autoConnect = serverconfig.auto_server
                if (!serverconfig.auto_server) {
                    Network.server = serverconfig.address
                }
                rootItem.close()
            }
        }
    }

    Component.onCompleted: {
        serverconfig.auto_server = Config.autoConnect
        serverconfig.address = Network.server
    }
}
