import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

WizardComponent {
    valid: true
    wizard_title: qsTr('Network Configuration')

    function apply() {
        wizard_data['use_defaults'] = !config_proxy.checked && !config_server.checked
        wizard_data['want_proxy'] = config_proxy.checked
        wizard_data['autoconnect'] = !config_server.checked
    }

    ColumnLayout {
        width: parent.width

        Label {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: parent.width
            text: qsTr("Optional settings to customize your network connection") + ":"
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHLeft
            font.pixelSize: constants.fontSizeLarge
        }

        ColumnLayout {
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: 2*constants.paddingXLarge; Layout.bottomMargin: 2*constants.paddingXLarge

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

        Label {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: parent.width
            text: qsTr("If you are unsure what this is, leave them unchecked and Electrum will automatically select servers.")
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHLeft
            font.pixelSize: constants.fontSizeMedium
        }
    }
}
