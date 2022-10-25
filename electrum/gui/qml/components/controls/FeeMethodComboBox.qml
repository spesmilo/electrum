import QtQuick 2.6
import QtQuick.Controls 2.0

import org.electrum 1.0

ComboBox {
    id: control

    required property QtObject feeslider

    textRole: 'text'
    valueRole: 'value'

    model: [
        { text: qsTr('ETA'), value: 1 },
        { text: qsTr('Mempool'), value: 2 },
        { text: qsTr('Static'), value: 0 }
    ]
    onCurrentValueChanged: {
        if (activeFocus)
            feeslider.method = currentValue
    }
    Component.onCompleted: {
        currentIndex = indexOfValue(feeslider.method)
    }
}
