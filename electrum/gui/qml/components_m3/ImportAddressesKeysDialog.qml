import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// Import of additional addresses (watch-only) or private keys into an imported wallet, Material 3 GUI; declared and
// opened by WalletDetailsPage ("Add addresses" / "Add keys"). A full-screen dialog.
// repeats: components/ImportAddressesKeysDialog.qml:8-133: the title by the kind of wallet, `valid`,
// verify() (Bitcoin.isAddressList / isPrivateKeyList), the import on accept (importAddresses / importPrivateKeys),
// the hint, the text box with its input hints, Paste (appends the clipboard on a new line when it verifies) and
// Scan (app.scanDialog with its hint; appends a scan that verifies, then closes the scanner), Import (enabled when
// valid, doAccept()), the secure window while the dialog is shown. Only the look differs.
// Strings keep the translation context of the classic file (qsTranslate('ImportAddressesKeysDialog', ...)).
M3FullScreenDialog {
    id: root

    title: Daemon.currentWallet.isWatchOnly
            ? qsTranslate('ImportAddressesKeysDialog', 'Import additional addresses')
            : qsTranslate('ImportAddressesKeysDialog', 'Import additional keys')

    property bool valid: false

    function verify(text) {
        if (Daemon.currentWallet.isWatchOnly)
            return bitcoin.isAddressList(text)
        else
            return bitcoin.isPrivateKeyList(text)
    }

    onAccepted: {
        if (Daemon.currentWallet.isWatchOnly)
            Daemon.currentWallet.importAddresses(import_ta.text)
        else
            Daemon.currentWallet.importPrivateKeys(import_ta.text)
    }

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
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                // the text box takes the free height of the screen, at least 5 lines
                height: Math.max(implicitHeight, flickable.height - 2 * m3.space16)
                spacing: m3.space16

                M3Text {
                    Layout.fillWidth: true
                    role: 'bodyMedium'
                    color: m3.surfaceVariantOn
                    wrapMode: Text.Wrap
                    lineHeightMode: Text.ProportionalHeight
                    lineHeight: 1.0
                    text: (Daemon.currentWallet.isWatchOnly
                            ? qsTranslate('ImportAddressesKeysDialog', 'Enter, paste or scan additional addresses')
                            : qsTranslate('ImportAddressesKeysDialog', 'Enter, paste or scan additional private keys')) +
                          '. ' + qsTranslate('ImportAddressesKeysDialog', 'You can add multiple, each on a separate line.')
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    spacing: m3.space4

                    M3TextArea {
                        id: import_ta
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        Layout.minimumHeight: 140
                        font.family: FixedFont
                        wrapMode: TextEdit.WrapAnywhere
                        onTextChanged: valid = verify(text)
                        inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                    }
                    ColumnLayout {
                        Layout.alignment: Qt.AlignTop
                        spacing: 0
                        M3IconButton {
                            tooltip: qsTr('Paste')
                            icon.source: Qt.resolvedUrl('../../icons/m3/content_paste.png')
                            onClicked: {
                                if (verify(AppController.clipboardToText())) {
                                    if (import_ta.text != '')
                                        import_ta.text = import_ta.text + '\n'
                                    import_ta.text = import_ta.text + AppController.clipboardToText()
                                }
                            }
                        }
                        M3IconButton {
                            tooltip: qsTr('Scan')
                            icon.source: Qt.resolvedUrl('../../icons/m3/qr_code_scanner.png')
                            onClicked: {
                                var dialog = app.scanDialog.createObject(app, {
                                    hint: Daemon.currentWallet.isWatchOnly
                                        ? qsTranslate('ImportAddressesKeysDialog', 'Scan another address')
                                        : qsTranslate('ImportAddressesKeysDialog', 'Scan another private key')
                                })
                                dialog.onFoundText.connect(function(data) {
                                    if (verify(data)) {
                                        if (import_ta.text != '')
                                            import_ta.text = import_ta.text + '\n'
                                        import_ta.text = import_ta.text + data
                                    }
                                    dialog.close()
                                })
                                dialog.open()
                            }
                        }
                    }
                }
            }
        }

        // --- Import (ImportAddressesKeysDialog.qml:113-119): below the content ---
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: importButton.implicitHeight + 2 * m3.space16
            color: m3.surface

            M3Button {
                id: importButton
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                variant: 'filled'
                size: 56
                icon.source: Qt.resolvedUrl('../../icons/m3/add.png')
                text: qsTranslate('ImportAddressesKeysDialog', 'Import')
                enabled: valid
                onClicked: doAccept()
            }
        }
    }

    Bitcoin {
        id: bitcoin
    }

    Binding {
        target: AppController
        property: 'secureWindow'
        when: root.visible  // enables stacking multiple secureWindow dialogs
        value: true
    }
}
