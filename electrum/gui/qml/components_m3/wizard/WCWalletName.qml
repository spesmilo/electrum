import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../controls"

// Material 3 page: name of the new wallet.
// repeats: components/wizard/WCWalletName.qml:7-32 @ e6df7e1c8 (valid by Daemon.isValidWalletName, apply(), the
// suggested name, the input method hints, the focus at the start).
WizardComponent {
    id: root
    valid: Daemon.isValidWalletName(wallet_name.text)

    function apply() {
        wizard_data['wallet_name'] = wallet_name.text
    }

    Flickable {
        id: flick
        anchors.fill: parent
        contentHeight: mainLayout.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        onHeightChanged: root.ensureVisible(flick, nameField)

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            M3Text {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                role: 'titleMedium'
                wrapMode: Text.Wrap
                text: qsTranslate('WCWalletName', 'Wallet name')
            }

            M3TextField {
                id: nameField
                Layout.fillWidth: true
                text: Daemon.suggestWalletName()
                inputMethodHints: Qt.ImhNoPredictiveText
                focus: true
            }
        }
    }

    // the TextField of the classic page
    readonly property Item wallet_name: nameField.field

    Component.onCompleted: {
        wallet_name.forceActiveFocus()
    }
}
