import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root
    securePage: true

    valid: false

    function apply() {
        if (bitcoin.isAddressList(import_ta.text)) {
            wizard_data['address_list'] = import_ta.text
        } else if (bitcoin.isPrivateKeyList(import_ta.text)) {
            wizard_data['private_key_list'] = import_ta.text
        }
    }

    function verify(text) {
        return bitcoin.isAddressList(text) || bitcoin.isPrivateKeyList(text)
    }

    ColumnLayout {
        width: parent.width

        InfoTextArea {
            Layout.preferredWidth: parent.width
            text: qsTr('Enter a list of Bitcoin addresses (this will create a watching-only wallet), or a list of private keys.')
        }

        RowLayout {
            Layout.topMargin: constants.paddingMedium
            TextArea {
                id: import_ta
                Layout.fillWidth: true
                Layout.minimumHeight: 80
                focus: true
                wrapMode: TextEdit.WrapAnywhere
                onTextChanged: valid = verify(text)
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
            }
            ColumnLayout {
                Layout.alignment: Qt.AlignTop
                ToolButton {
                    icon.source: '../../../icons/paste.png'
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
                    icon.source: '../../../icons/qrcode.png'
                    icon.height: constants.iconSizeMedium
                    icon.width: constants.iconSizeMedium
                    scale: 1.2
                    onClicked: {
                        var dialog = app.scanDialog.createObject(app, {
                            hint: bitcoin.isAddressList(import_ta.text)
                                ? qsTr('Scan another address')
                                : bitcoin.isPrivateKeyList(import_ta.text)
                                    ? qsTr('Scan another private key')
                                    : qsTr('Scan a private key or an address')
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
    }

    Bitcoin {
        id: bitcoin
    }

}
