import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: root

    property var invoiceParser  // type: InvoiceParser
    property var piResolver  // type: PIResolver

    // the manual entry dialog, while open. It stays open until the entered text is
    // accepted (which closes this dialog as well), or until the user cancels it.
    property var _manualEntryDialog

    signal txFound(data: string)
    signal channelBackupFound(data: string)

    width: parent.width
    height: parent.height

    header: null
    padding: 0
    topPadding: app.statusBarHeight

    onAboutToHide: {
        console.log('about to hide')
        qrscan.stop()
        if (_manualEntryDialog) {
            // close without transition, so it is gone before this dialog gets destroyed
            _manualEntryDialog.exit = null
            _manualEntryDialog.close()
        }
    }

    onTxFound: (data) => {
        app.stack.push(Qt.resolvedUrl('TxDetails.qml'), { rawtx: data })
        close()
    }

    onChannelBackupFound: (data) => {
        if (!Daemon.currentWallet.isLightning) {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Cannot import Channel Backup, Lightning not enabled.')
            })
            dialog.open()
            return
        }

        var dialog = app.messageDialog.createObject(app, {
            title: qsTr('Import Channel Backup?'),
            yesno: true
        })
        dialog.accepted.connect(function() {
            Daemon.currentWallet.importChannelBackup(data)
            close()
        })
        dialog.rejected.connect(function() {
            close()
        })
        dialog.open()
    }

    onClosed: destroy()

    function restart() {
        if (_manualEntryDialog)  // scanning resumes when the manual entry dialog is cancelled
            return
        qrscan.restart()
    }

    function dispatch(data) {
        data = data.trim()
        if (bitcoin.isRawTx(data)) {
            txFound(data)
        } else if (Daemon.currentWallet.isValidChannelBackup(data)) {
            channelBackupFound(data)
        } else {
            piResolver.recipient = data
        }
    }

    // override
    function doClose() {
        console.log('SendDialog doClose override') // doesn't trigger when going back??
        qrscan.stop()
        Qt.callLater(doReject)
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        QRScan {
            id: qrscan
            Layout.fillWidth: true
            Layout.fillHeight: true

            hint: Daemon.currentWallet.isLightning
                ? qsTr('Scan an Invoice, an Address, an LNURL, a PSBT or a Channel Backup')
                : qsTr('Scan an Invoice, an Address, an LNURL or a PSBT')

            onFoundText: (data) => {
                root.dispatch(data)
            }
        }

        DialogButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                enabled: !invoiceParser.busy && !piResolver.busy
                icon.source: '../../icons/pen.png'
                text: qsTr('Enter manually')
                onClicked: {
                    qrscan.stop()
                    root._manualEntryDialog = manualEntryDialog.createObject(app)
                    root._manualEntryDialog.rejected.connect(function() {
                        root._manualEntryDialog = null
                        root.restart()
                    })
                    root._manualEntryDialog.open()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                enabled: !invoiceParser.busy && !piResolver.busy
                icon.source: '../../icons/copy_bw.png'
                text: qsTr('Paste')
                onClicked: {
                    var cliptext = AppController.clipboardToText().trim()
                    if (!cliptext) {
                        toaster.show(this, qsTr('Clipboard is empty'))
                        return
                    }
                    qrscan.stop()
                    root.dispatch(cliptext)
                }
            }
        }

    }

    Bitcoin {
        id: bitcoin
    }

    Toaster {
        id: toaster
    }

    Component {
        id: manualEntryDialog
        ElDialog {
            id: dialog

            title: qsTr('Enter recipient')
            iconSource: Qt.resolvedUrl('../../icons/pen.png')

            width: parent.width * 4/5
            anchors.centerIn: parent
            padding: 0
            needsSystemBarPadding: false
            focus: true
            // resolving cannot be cancelled, so don't allow closing while busy
            allowClose: !root.piResolver.busy

            function submit() {
                // release focus, so the keyboard stays hidden when the field is re-enabled
                dialog.contentItem.forceActiveFocus()
                Qt.inputMethod.hide()
                root.dispatch(recipient.text)
            }

            ColumnLayout {
                width: parent.width
                spacing: 0

                TextField {
                    id: recipient
                    Layout.fillWidth: true
                    Layout.leftMargin: constants.paddingXXLarge
                    Layout.rightMargin: constants.paddingXXLarge
                    Layout.bottomMargin: constants.paddingLarge
                    focus: true
                    enabled: !root.piResolver.busy
                    rightPadding: spinner.visible ? spinner.width + constants.paddingSmall : leftPadding
                    placeholderText: qsTr('Recipient')
                    inputMethodHints: Qt.ImhEmailCharactersOnly | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                    EnterKey.type: Qt.EnterKeyDone
                    onAccepted: {
                        if (text.trim())
                            dialog.submit()
                    }

                    BusyIndicator {
                        id: spinner
                        anchors.right: parent.right
                        anchors.rightMargin: constants.paddingXSmall
                        anchors.verticalCenter: parent.verticalCenter
                        width: constants.iconSizeLarge
                        height: constants.iconSizeLarge
                        visible: root.piResolver.busy
                        running: visible
                    }
                }

                DialogButtonContainer {
                    Layout.fillWidth: true

                    FlatButton {
                        Layout.fillWidth: true
                        enabled: !root.piResolver.busy && recipient.text.trim()
                        icon.source: '../../icons/confirmed.png'
                        text: qsTr('Ok')
                        onClicked: dialog.submit()
                    }
                }
            }

            onClosed: destroy()
        }
    }

    // Keep the camera preview out of screenshots and screen recordings.
    Binding {
        target: AppController
        property: 'secureWindow'
        when: root.visible  // enables stacking multiple secureWindow dialogs
        value: true
    }
}
