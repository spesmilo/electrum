import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "../../../gui/qml/components/wizard"

WizardComponent {
    valid: true

    property QtObject plugin

    ColumnLayout {
        width: parent.width

        Image {
            Layout.alignment: Qt.AlignHCenter
            Layout.bottomMargin: constants.paddingLarge
            source: '../../../gui/icons/trustedcoin-wizard.png'
        }

        Label {
            Layout.fillWidth: true
            text: plugin ? plugin.disclaimer : ''
            wrapMode: Text.Wrap
        }
    }

    Component.onCompleted: {
        plugin = AppController.plugin('trustedcoin')
    }
}
