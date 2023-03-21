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
    iconSource: Qt.resolvedUrl('../../icons/lightning_disconnected.png')

    property bool _closing: false

    closePolicy: Popup.NoAutoClose

    padding: 0

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.preferredWidth: parent.width
            Layout.fillHeight: true

            leftMargin: constants.paddingLarge
            rightMargin: constants.paddingLarge

            contentHeight: rootLayout.height
            clip:true
            interactive: height < contentHeight

            GridLayout {
                id: rootLayout
                width: parent.width
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
                    text: qsTr('Short channel ID')
                    color: Material.accentColor
                }

                Label {
                    text: channeldetails.short_cid
                }

                Label {
                    text: qsTr('Remote node ID')
                    Layout.columnSpan: 2
                    color: Material.accentColor
                }

                TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true

                    Label {
                        width: parent.width
                        text: channeldetails.pubkey
                        font.pixelSize: constants.fontSizeLarge
                        font.family: FixedFont
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                    }
                }

                Item { Layout.preferredHeight: constants.paddingMedium; Layout.preferredWidth: 1; Layout.columnSpan: 2 }

                InfoTextArea {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    Layout.bottomMargin: constants.paddingLarge
                    text: channeldetails.message_force_close
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
                        id: closetypeCoop
                        ButtonGroup.group: closetypegroup
                        property string closetype: 'cooperative'
                        enabled: !_closing && channeldetails.canCoopClose
                        text: qsTr('Cooperative close')
                    }
                    RadioButton {
                        id: closetypeRemoteForce
                        ButtonGroup.group: closetypegroup
                        property string closetype: 'remote_force'
                        enabled: !_closing && channeldetails.canForceClose
                        text: qsTr('Request Force-close')
                    }
                    RadioButton {
                        id: closetypeLocalForce
                        ButtonGroup.group: closetypegroup
                        property string closetype: 'local_force'
                        enabled: !_closing && channeldetails.canForceClose && !channeldetails.isBackup
                        text: qsTr('Local Force-close')
                    }
                }

                ColumnLayout {
                    Layout.columnSpan: 2
                    Layout.maximumWidth: parent.width

                    InfoTextArea {
                        id: errorText
                        Layout.alignment: Qt.AlignHCenter
                        Layout.maximumWidth: parent.width
                        visible: !_closing && errorText.text
                        iconStyle: InfoTextArea.IconStyle.Error
                    }
                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: qsTr('Closing...')
                        visible: _closing
                    }
                    BusyIndicator {
                        Layout.alignment: Qt.AlignHCenter
                        visible: _closing
                    }
                }
            }
        }

        FlatButton {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            text: qsTr('Close channel')
            icon.source: '../../icons/closebutton.png'
            enabled: !_closing
            onClicked: {
                _closing = true
                channeldetails.closeChannel(closetypegroup.checkedButton.closetype)
            }

        }

    }

    ChannelDetails {
        id: channeldetails
        wallet: Daemon.currentWallet
        channelid: dialog.channelid

        onChannelChanged : {
            // init default choice
            if (channeldetails.canCoopClose)
                closetypeCoop.checked = true
            else
                closetypeRemoteForce.checked = true
        }

        onChannelCloseSuccess: {
            _closing = false
            dialog.close()
        }

        onChannelCloseFailed: {
            _closing = false
            errorText.text = message
        }
    }

}
