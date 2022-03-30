import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Dialog {
    id: dialog
    title: qsTr('Payment Request')

    property var modelItem

    parent: Overlay.overlay
    modal: true

    width: parent.width - constants.paddingXLarge
    height: parent.height - constants.paddingXLarge
    x: (parent.width - width) / 2
    y: (parent.height - height) / 2

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    header: RowLayout {
        width: dialog.width
        Label {
            Layout.fillWidth: true
            text: dialog.title
            visible: dialog.title
            elide: Label.ElideRight
            padding: 24
            bottomPadding: 0
            font.bold: true
            font.pixelSize: 16
        }
        ToolButton {
            Layout.alignment: Qt.AlignBaseline
            icon.source: '../../icons/closebutton.png'
            icon.color: 'transparent'
            icon.width: 32
            icon.height: 32
            onClicked: dialog.close()
        }
    }
    GridLayout {
        width: parent.width
        rowSpacing: constants.paddingXLarge
        columns: 3

        Rectangle {
            height: 1
            Layout.fillWidth: true
            Layout.columnSpan: 3
            color: Material.accentColor
        }

        Image {
            Layout.columnSpan: 3
            Layout.alignment: Qt.AlignHCenter
            source: 'image://qrgen/' + modelItem.address

            Rectangle {
                property int size: 57 // should be qr pixel multiple
                color: 'white'
                x: (parent.width - size) / 2
                y: (parent.height - size) / 2
                width: size
                height: size

                Image {
                    source: '../../icons/electrum.png'
                    x: 1
                    y: 1
                    width: parent.width - 2
                    height: parent.height - 2
                    scale: 0.9
                }
            }
        }

        Rectangle {
            height: 1
            Layout.fillWidth: true
            Layout.columnSpan: 3
            color: Material.accentColor
        }

        Label {
            visible: modelItem.message != ''
            text: qsTr('Description')
        }
        Label {
            visible: modelItem.message != ''
            Layout.columnSpan: 2
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: modelItem.message
            font.pixelSize: constants.fontSizeLarge
        }

        Label {
            visible: modelItem.amount > 0
            text: qsTr('Amount')
        }
        Label {
            visible: modelItem.amount > 0
            text: Config.formatSats(modelItem.amount, false)
            font.family: FixedFont
            font.pixelSize: constants.fontSizeLarge
        }
        Label {
            visible: modelItem.amount > 0
            Layout.fillWidth: true
            text: Config.baseUnit
            color: Material.accentColor
            font.pixelSize: constants.fontSizeLarge
        }

        Label {
            text: qsTr('Address')
        }
        Label {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            font.family: FixedFont
            font.pixelSize: constants.fontSizeLarge
            wrapMode: Text.WrapAnywhere
            text: modelItem.address
        }

        Label {
            text: qsTr('Status')
        }
        Label {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            font.pixelSize: constants.fontSizeLarge
            text: modelItem.status
        }

        RowLayout {
            Layout.columnSpan: 3
            Layout.fillHeight: true
            Layout.alignment: Qt.AlignHCenter
            Button {
                text: 'Delete'
                onClicked: {
                    Daemon.currentWallet.delete_request(modelItem.key)
                    dialog.close()
                }
            }
            Button {
                text: 'Copy'
                enabled: false
            }
            Button {
                text: 'Share'
                enabled: false
            }
        }
    }

}
