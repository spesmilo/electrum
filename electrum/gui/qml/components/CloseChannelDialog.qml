import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    width: parent.width
    height: parent.height

    property string channelid

    title: qsTr('Close Channel')
    iconSource: Qt.resolvedUrl('../../icons/lightning_disconnected.png')

    property string _closing_method

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
                    text: channeldetails.shortCid
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
                    text: channeldetails.messageForceClose
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

                    ElRadioButton {
                        id: closetypeCoop
                        ButtonGroup.group: closetypegroup
                        property string closetype: 'cooperative'
                        enabled: !channeldetails.isClosing && channeldetails.canCoopClose
                        text: qsTr('Cooperative close')
                    }
                    ElRadioButton {
                        id: closetypeRemoteForce
                        ButtonGroup.group: closetypegroup
                        property string closetype: 'remote_force'
                        enabled: !channeldetails.isClosing && channeldetails.canRequestForceClose
                        text: qsTr('Request Force-close')
                    }
                    ElRadioButton {
                        id: closetypeLocalForce
                        ButtonGroup.group: closetypegroup
                        property string closetype: 'local_force'
                        enabled: !channeldetails.isClosing && channeldetails.canLocalForceClose && !channeldetails.isBackup
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
                        visible: !channeldetails.isClosing && errorText.text
                        iconStyle: InfoTextArea.IconStyle.Error
                    }
                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: qsTr('Closing...')
                        visible: channeldetails.isClosing
                    }
                    BusyIndicator {
                        Layout.alignment: Qt.AlignHCenter
                        visible: channeldetails.isClosing
                    }
                }
            }
        }

        FlatButton {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            text: qsTr('Close channel')
            icon.source: '../../icons/closebutton.png'
            enabled: !channeldetails.isClosing
            onClicked: {
                if (closetypegroup.checkedButton.closetype == 'local_force') {
                    showBackupThenClose()
                } else {
                    doCloseChannel()
                }
            }
        }
    }

    function showBackupThenClose() {
        var sharedialog = app.genericShareDialog.createObject(app, {
            title: qsTr('Save channel backup and force close'),
            text_qr: channeldetails.channelBackup(),
            text_help: channeldetails.messageForceCloseBackup,
            helpTextIconStyle: InfoTextArea.IconStyle.Warn
        })
        sharedialog.closed.connect(function() {
            doCloseChannel()
        })
        sharedialog.open()
    }

    function doCloseChannel() {
        _closing_method = closetypegroup.checkedButton.closetype
        channeldetails.closeChannel(_closing_method)
    }

    function showCloseMessage(text) {
        var msgdialog = app.messageDialog.createObject(app, {
            text: text
        })
        msgdialog.open()
    }

    ChannelDetails {
        id: channeldetails
        wallet: Daemon.currentWallet
        channelid: dialog.channelid

        onAuthRequired: (method, authMessage) => {
            app.handleAuthRequired(channeldetails, method, authMessage)
        }

        onChannelChanged: {
            if (!channeldetails.canClose || channeldetails.isClosing)
                return

            // init default choice
            if (channeldetails.canCoopClose)
                closetypeCoop.checked = true
            else if (channeldetails.canRequestForceClose)
                closetypeRemoteForce.checked = true
            else
                closetypeLocalForce.checked = true
        }

        onChannelCloseSuccess: {
            if (_closing_method == 'local_force') {
                showCloseMessage(qsTr('Channel closed. You may need to wait at least %1 blocks, because of CSV delays').arg(channeldetails.toSelfDelay))
            } else if (_closing_method == 'remote_force') {
                showCloseMessage(qsTr('Request sent'))
            } else if (_closing_method == 'cooperative') {
                showCloseMessage(qsTr('Channel closed'))
            }
            dialog.close()
        }

        onChannelCloseFailed: (message) => {
            errorText.text = message
        }
    }

}
