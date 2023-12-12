import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "../../../gui/qml/components/wizard"
import "../../../gui/qml/components/controls"

WizardComponent {
    valid: !plugin ? false
                   : tosShown

    property QtObject plugin
    property bool tosShown: false

    ColumnLayout {
        anchors.fill: parent

        Label {
            text: qsTr('Terms and conditions')
        }

        TextHighlightPane {
            Layout.fillWidth: true
            Layout.fillHeight: true
            rightPadding: 0

            Flickable {
                anchors.fill: parent
                contentHeight: termsText.height
                clip: true
                boundsBehavior: Flickable.StopAtBounds

                Label {
                    id: termsText
                    width: parent.width
                    rightPadding: constants.paddingSmall
                    wrapMode: Text.Wrap
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
