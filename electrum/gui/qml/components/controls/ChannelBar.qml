import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material

import org.electrum 1.0

Item {
    property var capacity  // type: Amount
    property var localCapacity  // type: Amount
    property var remoteCapacity  // type: Amount
    property var canSend  // type: Amount
    property var canReceive  // type: Amount
    property bool frozenForSending: false
    property bool frozenForReceiving: false

    height: 10
    implicitWidth: 100

    function update() {
        Qt.callLater(do_update)
    }

    function do_update() {
        var cap = capacity.satsInt
        var twocap = cap * 2
        l1.width = width * (cap - localCapacity.satsInt) / twocap
        if (frozenForSending) {
            l2.width = width * localCapacity.satsInt / twocap
            l3.width = 0
        } else {
            l2.width = width * (localCapacity.satsInt - canSend.satsInt) / twocap
            l3.width = width * canSend.satsInt / twocap
        }
        if (frozenForReceiving) {
            r3.width = 0
            r2.width = width * remoteCapacity.satsInt / twocap
        } else {
            r3.width = width * canReceive.satsInt / twocap
            r2.width = width * (remoteCapacity.satsInt - canReceive.satsInt) / twocap
        }
        r1.width = width * (cap - remoteCapacity.satsInt) / twocap
    }

    onWidthChanged: update()
    onFrozenForSendingChanged: update()
    onFrozenForReceivingChanged: update()

    Connections {
        target: localCapacity
        function onValueChanged() { update() }
    }

    Connections {
        target: remoteCapacity
        function onValueChanged() { update() }
    }

    Connections {
        target: canSend
        function onValueChanged() { update() }
    }

    Connections {
        target: canReceive
        function onValueChanged() { update() }
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
