import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Item {
    property Amount capacity
    property Amount localCapacity
    property Amount remoteCapacity

    height: 10
    implicitWidth: 100

    onWidthChanged: {
        var cap = capacity.satsInt * 1000
        var twocap = cap * 2
        b1.width = width * (cap - localCapacity.msatsInt) / twocap
        b2.width = width * localCapacity.msatsInt / twocap
        b3.width = width * remoteCapacity.msatsInt / twocap
        b4.width = width * (cap - remoteCapacity.msatsInt) / twocap
    }
    Rectangle {
        id: b1
        x: 0
        height: parent.height
        color: 'gray'
    }
    Rectangle {
        id: b2
        anchors.left: b1.right
        height: parent.height
        color: constants.colorLightningLocal
    }
    Rectangle {
        id: b3
        anchors.left: b2.right
        height: parent.height
        color: constants.colorLightningRemote
    }
    Rectangle {
        id: b4
        anchors.left: b3.right
        height: parent.height
        color: 'gray'
    }
}
