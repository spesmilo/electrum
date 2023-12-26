import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

WizardComponent {
    valid: true
    wizard_title: qsTr('Electrum Groestlcoin Wallet')

    function apply() {
        wizard_data['use_defaults'] = !config_advanced.checked
        wizard_data['want_proxy'] = config_advanced.checked && config_proxy.checked
        wizard_data['autoconnect'] = !config_server.checked || !config_advanced.checked
    }

    ColumnLayout {
        width: parent.width

        Image {
            Layout.fillWidth: true
            fillMode: Image.PreserveAspectFit
            source: Qt.resolvedUrl('../../../icons/electrum_presplash.png')
            // reduce spacing a bit
            Layout.topMargin: -50
            Layout.bottomMargin: -120
        }

        CheckBox {
            id: config_advanced
            Layout.alignment: Qt.AlignHCenter
            text: qsTr('Advanced network settings')
            checked: false
            onCheckedChanged: checkIsLast()
        }

        ColumnLayout {
            Layout.alignment: Qt.AlignHCenter

            opacity: config_advanced.checked ? 1 : 0
            Behavior on opacity {
                NumberAnimation { duration: 300 }
            }

            CheckBox {
                id: config_proxy
                text: qsTr('Configure Proxy')
                checked: false
                onCheckedChanged: checkIsLast()
            }
            CheckBox {
                id: config_server
                text: qsTr('Select Server')
                checked: false
                onCheckedChanged: checkIsLast()
            }
        }
    }
}
