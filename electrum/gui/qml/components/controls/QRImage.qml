import QtQuick 2.6
import QtQuick.Controls 2.15

Item {
    id: root
    property string qrdata
    property bool render: true // init to false, then set true if render needs delay
    property var qrprops: QRIP.getDimensions(qrdata)

    width: r.width
    height: r.height

    Rectangle {
        id: r
        width: qrprops.modules * qrprops.box_size
        height: width
        color: 'white'
    }

    Image {
        source: qrdata && render ? 'image://qrgen/' + qrdata : ''

        Rectangle {
            visible: root.render && qrprops.valid
            color: 'white'
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: qrprops.icon_modules * qrprops.box_size
            height: qrprops.icon_modules * qrprops.box_size

            Image {
                visible: qrprops.valid
                source: '../../../icons/electrum.png'
                x: 1
                y: 1
                width: parent.width - 2
                height: parent.height - 2
                scale: 0.9
            }
        }
        Label {
            visible: !qrprops.valid
            text: qsTr('Data too big for QR')
            anchors.centerIn: parent
        }
    }
}
