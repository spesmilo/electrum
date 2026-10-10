import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum

import "controls"

ElDialog {
    id: dialog

    title: qsTr('Sign transaction')
    iconSource: Qt.resolvedUrl('../../icons/key.png')

    property var summary
    property string psbt
    property string password

    anchors.centerIn: parent
    width: parent.width * 4/5
    padding: 0

    function signAndBroadcast() {
        // the password was needed to read the transaction, so we have it already
        Cosigner.signAndBroadcast(psbt, password)
        dialog.close()
    }

    ColumnLayout {
        width: parent.width
        spacing: 0

        ColumnLayout {
            Layout.margins: constants.paddingLarge
            Layout.fillWidth: true

            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: qsTr('This transaction was created by a wallet that this device signs for.')
            }

            InfoTextArea {
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingMedium
                visible: summary['warning']
                iconStyle: InfoTextArea.IconStyle.Warn
                text: summary['warning'] ? summary['warning'] : ''
            }

            Label {
                Layout.topMargin: constants.paddingMedium
                text: qsTr('Outputs')
                color: Material.accentColor
            }

            Repeater {
                model: summary['outputs']
                delegate: RowLayout {
                    Layout.fillWidth: true
                    Label {
                        Layout.fillWidth: true
                        text: modelData['is_change']
                            ? modelData['address'] + ' (' + qsTr('change') + ')'
                            : modelData['address']
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeSmall
                        wrapMode: Text.WrapAnywhere
                    }
                    Label {
                        text: modelData['value']
                        font.family: FixedFont
                    }
                }
            }

            GridLayout {
                Layout.topMargin: constants.paddingMedium
                Layout.fillWidth: true
                columns: 2

                Label {
                    text: qsTr('Amount')
                    color: Material.accentColor
                }
                Label {
                    Layout.fillWidth: true
                    text: summary['amount']
                    font.family: FixedFont
                }
                Label {
                    text: qsTr('Mining fee')
                    color: Material.accentColor
                }
                Label {
                    Layout.fillWidth: true
                    text: summary['fee']
                    font.family: FixedFont
                }
            }
        }

        DialogButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Cancel')
                icon.source: Qt.resolvedUrl('../../icons/closebutton.png')
                onClicked: dialog.close()
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Sign and broadcast')
                icon.source: Qt.resolvedUrl('../../icons/key.png')
                onClicked: dialog.signAndBroadcast()
            }
        }
    }
}
