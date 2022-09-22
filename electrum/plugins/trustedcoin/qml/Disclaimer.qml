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

        Label {
            Layout.preferredWidth: parent.width
            text: plugin ? plugin.disclaimer : ''
            wrapMode: Text.Wrap
        }
    }

    Component.onCompleted: {
        plugin = AppController.plugin('trustedcoin')
    }
}
