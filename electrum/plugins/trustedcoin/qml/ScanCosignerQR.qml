import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "../../../gui/qml/components/wizard"
import "../../../gui/qml/components/controls"

WizardComponent {
    id: root
    securePage: true

    valid: false

    property QtObject plugin
    property string _qrdata

    function apply() {
        wizard_data['trustedcoin_cosigner_qr'] = _qrdata
    }

    ColumnLayout {
        width: parent.width

        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            text: [
                qsTr('On Electrum desktop, restore your 2FA seed, and choose to keep two-factor authentication with Electrum on your phone as cosigner.'),
                qsTr('Then, scan the QR code displayed by the desktop wizard.')
            ].join(' ')
        }

        Button {
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: constants.paddingLarge
            icon.source: '../../../gui/icons/qrcode.png'
            text: qsTr('Scan QR code')
            onClicked: {
                var dialog = app.scanDialog.createObject(app, {
                    hint: qsTr('Scan the cosigner QR code displayed by Electrum desktop')
                })
                dialog.onFoundText.connect(function(data) {
                    dialog.close()
                    if (plugin.isCosignerQr(data)) {
                        _qrdata = data
                        valid = true
                    } else {
                        _qrdata = ''
                        valid = false
                        errorBox.text = qsTr('This is not a 2FA cosigner QR code.')
                    }
                })
                dialog.open()
            }
        }

        InfoTextArea {
            id: errorBox
            Layout.fillWidth: true
            Layout.topMargin: constants.paddingLarge
            iconStyle: InfoTextArea.IconStyle.Error
            visible: !valid && text
        }

        Label {
            Layout.fillWidth: true
            Layout.topMargin: constants.paddingLarge
            visible: valid
            wrapMode: Text.Wrap
            text: qsTr('QR code scanned. Electrum will create the cosigner wallet on this device.')
        }

        Image {
            Layout.alignment: Qt.AlignHCenter
            source: '../../../gui/icons/confirmed.png'
            visible: valid
            Layout.preferredWidth: constants.iconSizeXLarge
            Layout.preferredHeight: constants.iconSizeXLarge
        }
    }

    Component.onCompleted: {
        plugin = AppController.plugin('trustedcoin')
    }
}
