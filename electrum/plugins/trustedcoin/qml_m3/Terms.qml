import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../../../gui/qml/components_m3/wizard"
import "../../../gui/qml/components_m3/controls"

// Material 3 page of the trustedcoin (2FA) wizard: the terms and conditions of the service, fetched from the server.
// Loaded only by the Material 3 wizard (table _m3PluginPages of components_m3/wizard/Wizard.qml).
// repeats: plugins/trustedcoin/qml/Terms.qml:9-172 (valid only with the plugin and once the terms were
// shown; plugin = AppController.plugin('trustedcoin') and fetchTermsAndConditions() on completion; the spinner while
// plugin.busy; termsAndConditionsRetrieved shows the text and allows Next, termsAndConditionsError shows the message).
// Look: the heading, then an M3Card over the rest of the height with the scrolling text
// (bodyMedium) and the spinner.
// Strings carried over keep the translation context of Terms.qml.
WizardComponent {
    valid: !plugin ? false
                   : tosShown

    property QtObject plugin
    property bool tosShown: false

    ColumnLayout {
        anchors.fill: parent
        spacing: m3.space16

        M3Text {
            Layout.fillWidth: true
            Layout.topMargin: m3.space8
            role: 'titleMedium'
            wrapMode: Text.Wrap
            text: qsTranslate('Terms', 'Terms and conditions')
        }

        M3Card {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.bottomMargin: m3.space16
            rightPadding: m3.space4

            Flickable {
                anchors.fill: parent
                contentHeight: termsText.height
                clip: true
                boundsBehavior: Flickable.StopAtBounds

                M3Text {
                    id: termsText
                    width: parent.width
                    rightPadding: m3.space12
                    role: 'bodyMedium'
                    wrapMode: Text.Wrap
                    textFormat: Text.AutoText  // as the classic Label
                }
                ScrollIndicator.vertical: ScrollIndicator { }
            }

            BusyIndicator {
                anchors.centerIn: parent
                visible: plugin ? plugin.busy : false
                running: visible
            }
        }
    }

    Component.onCompleted: {
        plugin = AppController.plugin('trustedcoin')
        plugin.fetchTermsAndConditions()
    }

    Connections {
        target: plugin
        function onTermsAndConditionsRetrieved(message) {
            termsText.text = message
            tosShown = true
        }
        function onTermsAndConditionsError(message) {
            termsText.text = message
        }
    }
}
