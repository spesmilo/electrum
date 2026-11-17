import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// "Close Channel" of the Material 3 GUI, opened by ChannelDetailsPage (zone probe R-3: a full-screen dialog, as
// the classic one).
// repeats: components/CloseChannelDialog.qml:10-242 @ e6df7e1c8: the contract (`channelid`), its own ChannelDetails
// object with onAuthRequired -> app.handleAuthRequired; channel name, short channel ID, remote node ID, the force
// close message; the three closing methods with their conditions (cooperative, request force-close, local
// force-close; none while closing) and the default choice on channelChanged (cooperative if possible, else request
// force-close, else local force-close; not while closing or when the channel cannot be closed); the error and
// "Closing..." with a spinner; Close channel (disabled while closing): a local force-close first shows the
// channel backup with the force-close backup message as a warning and closes the channel when that dialog closes,
// the other methods close directly; on success the message of the method, then the dialog closes; on failure the
// error.
// Look: the details as M3DetailRow rows, the methods as M3RadioRow rows in a group, the main button in the bar at
// the bottom (TxDialogButtonBar).
// Strings keep the translation context of the classic file (qsTranslate('CloseChannelDialog', ...)).
M3FullScreenDialog {
    id: dialog

    property string channelid

    title: qsTranslate('CloseChannelDialog', 'Close Channel')
    iconSource: Qt.resolvedUrl('../../icons/m3/link_off.png')

    property string _closing_method

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentHeight: content.implicitHeight + 2 * m3.space16
            interactive: height < contentHeight
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: content
                readonly property int margin: m3.screenMargin(dialog.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                spacing: m3.space16

                M3ListGroup {
                    Layout.fillWidth: true

                    M3DetailRow {
                        visible: channeldetails.name
                        label: qsTranslate('CloseChannelDialog', 'Channel name')
                        text: channeldetails.name
                    }

                    M3DetailRow {
                        label: qsTranslate('CloseChannelDialog', 'Short channel ID')
                        text: channeldetails.shortCid
                    }

                    M3DetailRow {
                        label: qsTranslate('CloseChannelDialog', 'Remote node ID')
                        text: channeldetails.pubkey
                        monospace: true
                    }
                }

                M3InfoText {
                    Layout.fillWidth: true
                    text: channeldetails.messageForceClose
                }

                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space8
                    leftPadding: 0
                    text: qsTranslate('CloseChannelDialog', 'Choose closing method')
                }

                ButtonGroup {
                    id: closetypegroup
                }

                M3ListGroup {
                    Layout.fillWidth: true

                    M3RadioRow {
                        id: closetypeCoop
                        ButtonGroup.group: closetypegroup
                        property string closetype: 'cooperative'
                        enabled: !channeldetails.isClosing && channeldetails.canCoopClose
                        text: qsTranslate('CloseChannelDialog', 'Cooperative close')
                    }
                    M3RadioRow {
                        id: closetypeRemoteForce
                        ButtonGroup.group: closetypegroup
                        property string closetype: 'remote_force'
                        enabled: !channeldetails.isClosing && channeldetails.canRequestForceClose
                        text: qsTranslate('CloseChannelDialog', 'Request Force-close')
                    }
                    M3RadioRow {
                        id: closetypeLocalForce
                        ButtonGroup.group: closetypegroup
                        property string closetype: 'local_force'
                        enabled: !channeldetails.isClosing && channeldetails.canLocalForceClose && !channeldetails.isBackup
                        text: qsTranslate('CloseChannelDialog', 'Local Force-close')
                    }
                }

                M3InfoText {
                    id: errorText
                    Layout.fillWidth: true
                    visible: !channeldetails.isClosing && errorText.text
                    iconStyle: M3InfoText.IconStyle.Error
                }

                RowLayout {
                    Layout.alignment: Qt.AlignHCenter
                    visible: channeldetails.isClosing
                    spacing: m3.space12

                    BusyIndicator {
                        Layout.preferredWidth: 32
                        Layout.preferredHeight: 32
                        running: channeldetails.isClosing
                    }
                    M3Text {
                        role: 'bodyLarge'
                        text: qsTranslate('CloseChannelDialog', 'Closing...')
                    }
                }
            }
        }

        TxDialogButtonBar {
            Layout.fillWidth: true
            text: qsTranslate('CloseChannelDialog', 'Close channel')
            icon.source: Qt.resolvedUrl('../../icons/m3/link_off.png')
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
            title: qsTranslate('CloseChannelDialog', 'Save channel backup and force close'),
            text_qr: channeldetails.channelBackup(),
            text_help: channeldetails.messageForceCloseBackup,
            helpTextIconStyle: M3InfoText.IconStyle.Warn
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
                showCloseMessage(qsTranslate('CloseChannelDialog', 'Channel closed. You may need to wait at least %1 blocks, because of CSV delays').arg(channeldetails.toSelfDelay))
            } else if (_closing_method == 'remote_force') {
                showCloseMessage(qsTranslate('CloseChannelDialog', 'Request sent'))
            } else if (_closing_method == 'cooperative') {
                showCloseMessage(qsTranslate('CloseChannelDialog', 'Channel closed'))
            }
            dialog.close()
        }

        onChannelCloseFailed: (message) => {
            errorText.text = message
        }
    }
}
