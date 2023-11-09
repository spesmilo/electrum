import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material

import org.electrum 1.0

Item {
    property Amount capacity
    property Amount localCapacity
    property Amount remoteCapacity
    property Amount canSend
    property Amount canReceive
    property bool frozenForSending: false
    property bool frozenForReceiving: false

    height: 10
    implicitWidth: 100

    function update() {
        Qt.callLater(do_update)
    }

    function do_update() {
        var cap = capacity.satsInt * 1000
        var twocap = cap * 2
        l1.width = width * (cap - localCapacity.msatsInt) / twocap
        if (frozenForSending) {
            l2.width = width * localCapacity.msatsInt / twocap
            l3.width = 0
        } else {
            l2.width = width * (localCapacity.msatsInt - canSend.msatsInt) / twocap
            l3.width = width * canSend.msatsInt / twocap
        }
        if (frozenForReceiving) {
            r3.width = 0
            r2.width = width * remoteCapacity.msatsInt / twocap
        } else {
            r3.width = width * canReceive.msatsInt / twocap
            r2.width = width * (remoteCapacity.msatsInt - canReceive.msatsInt) / twocap
        }
        r1.width = width * (cap - remoteCapacity.msatsInt) / twocap
    }

    onWidthChanged: update()
    onFrozenForSendingChanged: update()
    onFrozenForReceivingChanged: update()

    Connections {
        target: localCapacity
        function onMsatsIntChanged() { update() }
    }

    Connections {
        target: remoteCapacity
        function onMsatsIntChanged() { update() }
    }

    Connections {
        target: canSend
        function onMsatsIntChanged() { update() }
    }

    Connections {
        target: canReceive
        function onMsatsIntChanged() { update() }
    }

    Rectangle {
        id: l1
        x: 0
        height: parent.height
        color: 'gray'
    }
    Rectangle {
        id: l2
        anchors.left: l1.right
        height: parent.height
        color: constants.colorLightningLocalReserve
    }
    Rectangle {
        id: l3
        anchors.left: l2.right
        height: parent.height
        color: constants.colorLightningLocal
    }
    Rectangle {
        id: r3
        anchors.left: l3.right
        height: parent.height
        color: constants.colorLightningRemote
    }
    Rectangle {
        id: r2
        anchors.left: r3.right
        height: parent.height
        color: constants.colorLightningRemoteReserve
    }
    Rectangle {
        id: r1
        anchors.left: r2.right
        height: parent.height
        color: 'gray'
    }
}
