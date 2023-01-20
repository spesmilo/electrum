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

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            ServerConfig {
                id: serverconfig
                Layout.fillWidth: true
                Layout.fillHeight: true
            }

        }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Ok')
            icon.source: '../../icons/confirmed.png'
            onClicked: {
                Config.autoConnect = serverconfig.auto_connect
                Config.serverString = serverconfig.address
                Network.server = serverconfig.address
                rootItem.close()
            }
        }
    }

}
