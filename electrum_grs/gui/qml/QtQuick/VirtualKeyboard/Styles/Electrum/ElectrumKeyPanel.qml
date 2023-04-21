import QtQuick 2.7
import QtQuick.VirtualKeyboard 2.1
import QtQuick.VirtualKeyboard.Styles 2.1

import org.electrum 1.0

KeyPanel {
    id: keyPanel
    Connections {
        target: keyPanel.control
        function onPressedChanged() {
            if (keyPanel.control.pressed)
                AppController.haptic()
        }
    }
}
