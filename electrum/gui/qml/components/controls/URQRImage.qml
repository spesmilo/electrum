import QtQuick
import QtQuick.Controls

import org.electrum 1.0

// Shows a (multi-part) BC-UR as animated QR code
Item {
    id: root
    property string urType
    property string payload  // hex

    // computed once: the size must not change during the animation
    property var _qrprops: ({ qr_pixelsize: 0 })
    Component.onCompleted: _qrprops = QRIP.getDimensions(encoder.currentPart)

    // implicit size: _qrprops is only set on completion, after layouts have read the size
    implicitWidth: r.width
    implicitHeight: r.height

    URQREncoder {
        id: encoder
        urType: root.urType
        payload: root.payload
    }

    Timer {
        interval: 200
        repeat: true
        running: encoder.isMultiPart && root.visible && Qt.application.state === Qt.ApplicationActive
        // rendering a part can take longer than the interval on slow devices: advance only once it is shown
        onTriggered: if (img.status !== Image.Loading) encoder.nextPart()
    }

    Rectangle {
        id: r
        // fixed size: the length of the parts varies slightly
        width: root._qrprops.qr_pixelsize
        height: width
        color: 'white'
    }

    Image {
        id: img
        anchors.fill: r
        source: encoder.currentPart ? 'image://qrgen/' + encoder.currentPart : ''
        fillMode: Image.PreserveAspectFit
        asynchronous: true
        cache: false
        retainWhileLoading: true
        smooth: false

        Rectangle {  // container for logo inside qr code, same as in QRImage
            visible: root._qrprops.valid
            color: 'white'
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: root._qrprops.icon_pixelsize
            height: root._qrprops.icon_pixelsize

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

    onVisibleChanged: {
        if (root.visible) {
            // set max brightness to make qr code easier to scan, same as in QRImage
            if (AppController.isMaxBrightnessOnQrDisplayEnabled()) {
                AppController.setMaxScreenBrightness()
            }
        } else {
            AppController.resetScreenBrightness()
        }
    }
}
