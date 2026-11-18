import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../controls"

// Material 3 page: import Bitcoin addresses (watching-only wallet) or private keys.
// repeats: components/wizard/WCImport.qml:9-98 (securePage, valid; apply() putting the text into
// address_list or private_key_list; verify(); the field verified on every change; paste appends a verified
// clipboard on a new line; scan (app.scanDialog with the hint by what the field holds, appends verified data,
// close)).
// Look: the explanation as M3InfoText, an outlined M3TextArea in the fixed font over
// the rest of the height with the icon buttons paste / scan beside it.
// Strings carried over keep the translation context of WCImport.qml.
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
        height: parent.height
        spacing: m3.space16

        M3InfoText {
            Layout.fillWidth: true
            Layout.topMargin: m3.space8
            compact: true
            text: qsTranslate('WCImport', 'Enter a list of Bitcoin addresses (this will create a watching-only wallet), or a list of private keys.')
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.bottomMargin: m3.space16
            spacing: m3.space4

            M3TextArea {
                id: import_ta
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.minimumHeight: 96
                font.family: FixedFont
                wrapMode: TextEdit.WrapAnywhere
                onTextChanged: valid = verify(text)
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
            }

            ColumnLayout {
                Layout.alignment: Qt.AlignTop
                spacing: 0
                M3IconButton {
                    icon.source: Qt.resolvedUrl('../../../icons/m3/content_paste.png')
                    tooltip: qsTranslate('SendDialog', 'Paste')
                    onClicked: {
                        if (verify(AppController.clipboardToText())) {
                            if (import_ta.text != '')
                                import_ta.text = import_ta.text + '\n'
                            import_ta.text = import_ta.text + AppController.clipboardToText()
                        }
                    }
                }
                M3IconButton {
                    icon.source: Qt.resolvedUrl('../../../icons/m3/qr_code_scanner.png')
                    tooltip: bitcoin.isAddressList(import_ta.text)
                        ? qsTranslate('WCImport', 'Scan another address')
                        : bitcoin.isPrivateKeyList(import_ta.text)
                            ? qsTranslate('WCImport', 'Scan another private key')
                            : qsTranslate('WCImport', 'Scan a private key or an address')
                    onClicked: {
                        var dialog = app.scanDialog.createObject(app, {
                            hint: bitcoin.isAddressList(import_ta.text)
                                ? qsTranslate('WCImport', 'Scan another address')
                                : bitcoin.isPrivateKeyList(import_ta.text)
                                    ? qsTranslate('WCImport', 'Scan another private key')
                                    : qsTranslate('WCImport', 'Scan a private key or an address')
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

    Bitcoin {
        id: bitcoin
    }

}
