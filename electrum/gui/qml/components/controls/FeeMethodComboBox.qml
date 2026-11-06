import QtQuick
import QtQuick.Controls

import org.electrum 1.0

ElComboBox {
    id: control

    required property QtObject feeslider

    textRole: 'text'
    valueRole: 'value'

    // NOTE: deadline property only exists on QETxFinalizer, but as undefined == false, that's ok.
    model: feeslider.deadline ? [
        { text: qsTr('ETA'), value: FeeSlider.FSMethod.ETA }
    ] : [
        { text: qsTr('ETA'), value: FeeSlider.FSMethod.ETA },
        { text: qsTr('Mempool'), value: FeeSlider.FSMethod.MEMPOOL },
        { text: qsTr('Feerate'), value: FeeSlider.FSMethod.FEERATE },
        { text: qsTr('Manual'), value: FeeSlider.FSMethod.MANUAL }
    ]
    onCurrentValueChanged: {
        if (activeFocus)
            feeslider.method = currentValue
    }
    Component.onCompleted: {
        currentIndex = indexOfValue(feeslider.method)
    }
}
