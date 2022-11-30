import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3

import org.electrum 1.0

import "controls"

ElDialog {
    id: root

    property bool valid: false

    standardButtons: Dialog.Cancel
    modal: true
    parent: Overlay.overlay
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }
    width: parent.width
    height: parent.height

    padding: 0

    title: qsTr('Import channel backup')
    iconSource: Qt.resolvedUrl('../../icons/file.png')

    function verifyChannelBackup(text) {
        return valid = Daemon.currentWallet.isValidChannelBackup(text)
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        RowLayout {
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingLarge

            TextArea {
                id: channelbackup_ta
                Layout.fillWidth: true
                Layout.minimumHeight: 80
                font.family: FixedFont
                focus: true
                wrapMode: TextEdit.WrapAnywhere
                onTextChanged: verifyChannelBackup(text)
            }
            ColumnLayout {
                ToolButton {
                    icon.source: '../../icons/paste.png'
                    icon.height: constants.iconSizeMedium
                    icon.width: constants.iconSizeMedium
                    onClicked: {
                        channelbackup_ta.text = AppController.clipboardToText()
                    }
                }
                ToolButton {
                    icon.source: '../../icons/qrcode.png'
                    icon.height: constants.iconSizeMedium
                    icon.width: constants.iconSizeMedium
                    scale: 1.2
                    onClicked: {
                        var scan = qrscan.createObject(root.contentItem)
                        scan.onFound.connect(function() {
                            channelbackup_ta.text = scan.scanData
                            scan.destroy()
                        })
                    }
                }
            }
        }

        TextArea {
            id: validationtext
            visible: text
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingLarge

            readOnly: true
            wrapMode: TextInput.WordWrap
            background: Rectangle {
                color: 'transparent'
            }
        }

        Item { Layout.preferredWidth: 1; Layout.fillHeight: true }

        FlatButton {
            Layout.fillWidth: true
            enabled: valid
            text: qsTr('Import')
            onClicked: {
                Daemon.currentWallet.importChannelBackup(channelbackup_ta.text)
                root.accept()
            }
        }
    }

    Component {
        id: qrscan
        QRScan {
            width: root.contentItem.width
            height: root.contentItem.height

            ToolButton {
                icon.source: '../../icons/closebutton.png'
                icon.height: constants.iconSizeMedium
                icon.width: constants.iconSizeMedium
                anchors.right: parent.right
                anchors.top: parent.top
                onClicked: {
                    parent.destroy()
                }
            }
        }
    }

}
