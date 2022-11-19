import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog
    width: parent.width
    height: parent.height

    property string channelid

    title: qsTr('Close Channel')
    standardButtons: closing ? 0 : Dialog.Cancel

    modal: true
    parent: Overlay.overlay
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }
    property bool closing: false

    closePolicy: Popup.NoAutoClose

    padding: 0

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        GridLayout {
            id: layout
            Layout.preferredWidth: parent.width - 2*constants.paddingLarge
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge
            columns: 2

            Label {
                Layout.fillWidth: true
                visible: channeldetails.name
                text: qsTr('Channel name')
                color: Material.accentColor
            }

            Label {
                Layout.fillWidth: true
                visible: channeldetails.name
                text: channeldetails.name
            }

            Label {
                text: qsTr('Remote node ID')
                Layout.columnSpan: 2
                color: Material.accentColor
            }

            TextHighlightPane {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                padding: 0
                leftPadding: constants.paddingSmall

                Label {
                    width: parent.width
                    text: channeldetails.pubkey
                    font.pixelSize: constants.fontSizeLarge
                    font.family: FixedFont
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                }
            }

            Label {
                text: qsTr('Short channel ID')
                color: Material.accentColor
            }

            Label {
                text: channeldetails.short_cid
            }

            Item { Layout.preferredHeight: constants.paddingMedium; Layout.preferredWidth: 1; Layout.columnSpan: 2 }

            InfoTextArea {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                text: qsTr(channeldetails.message_force_close)
            }

            Label {
                text: qsTr('Choose closing method')
                Layout.columnSpan: 2
                color: Material.accentColor
            }

            ColumnLayout {
                Layout.columnSpan: 2
                Layout.alignment: Qt.AlignHCenter

                ButtonGroup {
                    id: closetypegroup
                }

                RadioButton {
                    ButtonGroup.group: closetypegroup
                    property string closetype: 'cooperative'
                    checked: true
                    enabled: !closing && channeldetails.canCoopClose
                    text: qsTr('Cooperative close')
                }
                RadioButton {
                    ButtonGroup.group: closetypegroup
                    property string closetype: 'remote_force'
                    enabled: !closing && channeldetails.canForceClose
                    text: qsTr('Request Force-close')
                }
                RadioButton {
                    ButtonGroup.group: closetypegroup
                    property string closetype: 'local_force'
                    enabled: !closing && channeldetails.canForceClose && !channeldetails.isBackup
                    text: qsTr('Local Force-close')
                }
            }

            ColumnLayout {
                Layout.columnSpan: 2
                Layout.alignment: Qt.AlignHCenter
                Label {
                    id: errorText
                    visible: !closing && errorText
                    wrapMode: Text.Wrap
                    Layout.preferredWidth: layout.width
                }
                Label {
                    text: qsTr('Closing...')
                    visible: closing
                }
                BusyIndicator {
                    visible: closing
                }
            }
        }

        Item { Layout.fillHeight: true; Layout.preferredWidth: 1 }

        FlatButton {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            text: qsTr('Close channel')
            icon.source: '../../icons/closebutton.png'
            enabled: !closing
            onClicked: {
                closing = true
                channeldetails.close_channel(closetypegroup.checkedButton.closetype)
            }

        }

    }

    ChannelDetails {
        id: channeldetails
        wallet: Daemon.currentWallet
        channelid: dialog.channelid

        onChannelCloseSuccess: {
            closing = false
            dialog.close()
        }

        onChannelCloseFailed: {
            closing = false
            errorText.text = message
        }
    }

}
