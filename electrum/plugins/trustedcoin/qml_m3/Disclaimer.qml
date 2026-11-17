import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../../../gui/qml/components_m3/wizard"
import "../../../gui/qml/components_m3/controls"

// Material 3 page of the trustedcoin (2FA) wizard: the disclaimer of the service. Loaded only by the Material 3
// wizard (components_m3/wizard/Wizard.qml, table _m3PluginPages: .../trustedcoin/qml/ -> .../trustedcoin/qml_m3/);
// the classic wizard keeps loading qml/Disclaimer.qml.
// repeats: plugins/trustedcoin/qml/Disclaimer.qml:9-32 @ e6df7e1c8 (valid, plugin =
// AppController.plugin('trustedcoin') on completion, the picture, the text plugin.disclaimer).
// Look (DESIGN-M2-onboarding.md 4): the colored picture of the service centered (not tinted), the disclaimer as
// bodyLarge text; the page scrolls.
WizardComponent {
    valid: true

    property QtObject plugin

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            Image {
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: m3.space16
                source: '../trustedcoin-wizard.png'
            }

            M3Text {
                Layout.fillWidth: true
                role: 'bodyLarge'
                wrapMode: Text.Wrap
                textFormat: Text.AutoText  // as the classic Label
                text: plugin ? plugin.disclaimer : ''
            }
        }
    }

    Component.onCompleted: {
        plugin = AppController.plugin('trustedcoin')
    }
}
