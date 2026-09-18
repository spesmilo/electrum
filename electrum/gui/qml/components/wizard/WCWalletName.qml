import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

WizardComponent {
    valid: Daemon.isValidWalletName(wallet_name.text)

    function apply() {
        wizard_data['wallet_name'] = wallet_name.text
    }

    ColumnLayout {
        width: parent.width

        Label {
            text: qsTr('Wallet name')
        }

        TextField {
            id: wallet_name
            Layout.fillWidth: true
            focus: true
            text: Daemon.suggestWalletName()
            inputMethodHints: Qt.ImhNoPredictiveText
        }

        ColumnLayout {
            id: pluginButtons
            Layout.fillWidth: true
            Layout.topMargin: constants.paddingLarge

            Component.onCompleted: {
                var buttons = app.pluginsComponentsByName('wizard_scan_button')
                for (var i=0; i < buttons.length; i++) {
                    var b = buttons[i].createObject(pluginButtons)
                    b.Layout.fillWidth = true
                }
            }
        }
    }

    Component.onCompleted: {
        wallet_name.forceActiveFocus()
    }
}
