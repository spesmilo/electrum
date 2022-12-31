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

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            ServerConfig {
                id: serverconfig
                Layout.fillWidth: true
            }

            Label {
                text: qsTr('Servers')
                font.pixelSize: constants.fontSizeLarge
                color: Material.accentColor
            }

            Rectangle {
                Layout.fillWidth: true
                height: 1
                color: Material.accentColor
            }

            Frame {
                background: PaneInsetBackground { baseColor: Material.dialogColor }
                clip: true
                verticalPadding: 0
                horizontalPadding: 0
                Layout.fillHeight: true
                Layout.fillWidth: true

                ListView {
                    id: serversListView
                    anchors.fill: parent
                    model: Network.serverListModel
                    delegate: ServerDelegate {}

                    section.property: 'chain'
                    section.criteria: ViewSection.FullString
                    section.delegate: RowLayout {
                        width: ListView.view.width
                        required property string section
                        Label {
                            text: section
                                ? serversListView.model.chaintips > 1
                                    ? qsTr('Connected @%1').arg(section)
                                    : qsTr('Connected')
                                : qsTr('Disconnected')
                            Layout.alignment: Qt.AlignLeft
                            Layout.topMargin: constants.paddingXSmall
                            Layout.leftMargin: constants.paddingSmall
                            font.pixelSize: constants.fontSizeMedium
                            color: Material.accentColor
                        }
                    }

                }
            }
        }

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
