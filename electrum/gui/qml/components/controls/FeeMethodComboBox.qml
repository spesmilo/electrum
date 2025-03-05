import QtQuick
import QtQuick.Controls

import org.electrum 1.0

ElComboBox {
    id: control

    required property QtObject feeslider

    textRole: 'text'
    valueRole: 'value'

    model: [
        { text: qsTr('ETA'), value: FeeSlider.FSMethod.ETA },
        { text: qsTr('Mempool'), value: FeeSlider.FSMethod.MEMPOOL },
        { text: qsTr('Feerate'), value: FeeSlider.FSMethod.FEERATE }
    ]
    onCurrentValueChanged: {
        if (activeFocus)
            feeslider.method = currentValue
    }
    Component.onCompleted: {
        currentIndex = indexOfValue(feeslider.method)
    }
}
