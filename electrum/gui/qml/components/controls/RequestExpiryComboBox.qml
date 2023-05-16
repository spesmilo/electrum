import QtQuick 2.6
import QtQuick.Controls 2.3

import org.electrum 1.0

ElComboBox {
    id: expires

    textRole: 'text'
    valueRole: 'value'

    model: ListModel {
        id: expiresmodel
        Component.onCompleted: {
            // we need to fill the model like this, as ListElement can't evaluate script
            expiresmodel.append({'text': qsTr('10 minutes'), 'value': 10*60})
            expiresmodel.append({'text': qsTr('1 hour'), 'value': 60*60})
            expiresmodel.append({'text': qsTr('1 day'), 'value': 24*60*60})
            expiresmodel.append({'text': qsTr('1 week'), 'value': 7*24*60*60})
            expiresmodel.append({'text': qsTr('1 month'), 'value': 31*24*60*60})
            expiresmodel.append({'text': qsTr('Never'), 'value': 0})
            expires.currentIndex = 0
            for (let i=0; i < expiresmodel.count; i++) {
                if (expiresmodel.get(i).value == Config.requestExpiry) {
                    expires.currentIndex = i
                    break
                }
            }
        }
    }

    onCurrentValueChanged: {
        if (activeFocus)
            Config.requestExpiry = currentValue
    }
}
