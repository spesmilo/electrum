import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

ElDialog {
    id: root

    title: Daemon.currentWallet.isWatchOnly
            ? qsTr('Import additional addresses')
            : qsTr('Import additional keys')

    property bool valid: false

    width: parent.width
    height: parent.height

    padding: 0

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

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: (Daemon.currentWallet.isWatchOnly
                        ? qsTr('Enter, paste or scan additional addresses')
                        : qsTr('Enter, paste or scan additional private keys')) +
                      '. ' + qsTr('You can add multiple, each on a separate line.')
            }

            RowLayout {
                ElTextArea {
                    id: import_ta
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    font.family: FixedFont
                    wrapMode: TextEdit.WrapAnywhere
                    onTextChanged: valid = verify(text)
                    inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                    background: PaneInsetBackground {
                        baseColor: constants.darkerDialogBackground
                    }
                }
                ColumnLayout {
                    Layout.alignment: Qt.AlignTop
                    ToolButton {
                        icon.source: '../../icons/paste.png'
                        icon.height: constants.iconSizeMedium
                        icon.width: constants.iconSizeMedium
                        onClicked: {
                            if (verify(AppController.clipboardToText())) {
                                if (import_ta.text != '')
                                    import_ta.text = import_ta.text + '\n'
                                import_ta.text = import_ta.text + AppController.clipboardToText()
                            }
                        }
                    }
                    ToolButton {
                        icon.source: '../../icons/qrcode.png'
                        icon.height: constants.iconSizeMedium
                        icon.width: constants.iconSizeMedium
                        scale: 1.2
                        onClicked: {
                            var dialog = app.scanDialog.createObject(app, {
                                hint: Daemon.currentWallet.isWatchOnly
                                    ? qsTr('Scan another address')
                                    : qsTr('Scan another private key')
                            })
                            dialog.onFound.connect(function() {
                                if (verify(dialog.scanData)) {
                                    if (import_ta.text != '')
                                        import_ta.text = import_ta.text + ',\n'
                                    import_ta.text = import_ta.text + dialog.scanData
                                }
                                dialog.close()
                            })
                            dialog.open()
                        }
                    }
                }
            }

            Item {
                Layout.preferredWidth: 1
                Layout.fillHeight: true
            }
        }

        FlatButton {
            Layout.fillWidth: true
            icon.source: '../../icons/add.png'
            text: qsTr('Import')
            enabled: valid
            onClicked: doAccept()
        }
    }

    Bitcoin {
        id: bitcoin
    }

}
