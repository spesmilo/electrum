import QtQuick 2.6

Image {
    property string qrdata

    source: qrdata ? 'image://qrgen/' + qrdata : ''

    Rectangle {
        property var qrprops: QRIP.getDimensions(qrdata)
        color: 'white'
        x: (parent.width - width) / 2
        y: (parent.height - height) / 2
        width: qrprops.icon_modules * qrprops.box_size
        height: qrprops.icon_modules * qrprops.box_size

        Image {
            source: '../../../icons/electrum.png'
            x: 1
            y: 1
            width: parent.width - 2
            height: parent.height - 2
            scale: 0.9
        }
    }
}
