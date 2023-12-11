import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

// import org.electrum 1.0

import "../controls"

WizardComponent {
    valid: true
    title: qsTr('Electrum Bitcoin Wallet')

    function apply() {
        wizard_data['use_defaults'] = use_defaults.checked
        if (use_defaults.checked) {
            wizard_data['autoconnect'] = true
            wizard_data['want_proxy'] = false
        }
    }

    ColumnLayout {
        width: parent.width

        Image {
            Layout.fillWidth: true
            fillMode: Image.PreserveAspectFit
            source: Qt.resolvedUrl('../../../icons/electrum_presplash.png')
            // reduce spacing a bit
            Layout.topMargin: -50
            Layout.bottomMargin: -160
        }

        Label {
            Layout.alignment: Qt.AlignHCenter
            text: qsTr('Welcome')
            font.pixelSize: constants.fontSizeXLarge
            Layout.bottomMargin: constants.paddingXXLarge
        }

        CheckBox {
            id: use_defaults
            Layout.alignment: Qt.AlignHCenter
            text: qsTr('Use default network settings')
            checked: true
            onCheckedChanged: checkIsLast()
        }
    }
}
