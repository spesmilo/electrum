import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "../../../gui/qml/components/wizard"
import "../../../gui/qml/components/controls"

WizardComponent {
    valid: !plugin ? false
                   : email.text.length > 0 // TODO: validate email address
                     && plugin.termsAndConditions

    property QtObject plugin

    onAccept: {
        wizard_data['2fa_email'] = email.text
    }

    ColumnLayout {
        anchors.fill: parent

        Label { text: qsTr('Terms and conditions') }

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
                    text: plugin ? plugin.termsAndConditions : ''
                }
                ScrollIndicator.vertical: ScrollIndicator { }
            }

            BusyIndicator {
                anchors.centerIn: parent
                visible: plugin ? plugin.busy : false
                running: visible
            }
        }

        Label { text: qsTr('Email') }

        TextField {
            id: email
            Layout.fillWidth: true
            placeholderText: qsTr('Enter your email address')
        }
    }

    Component.onCompleted: {
        plugin = AppController.plugin('trustedcoin')
        plugin.fetchTermsAndConditions()
    }
}
