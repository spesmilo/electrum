import QtQuick
import QtQuick.Controls

// QR code of the Material 3 GUI.
// repeats: components/controls/QRImage.qml:1-92 @ e6df7e1c8 (qrdata, render, enableToggleText, isTextState,
// clicked(), QRIP dimensions, the logo in the middle, the encoded text on tap, max screen brightness while
// visible). The QR stays black on white in both themes (scanners need it); Material 3 adds only a white
// rounded frame (radius M, quiet zone of m3.space8 around the code), so on a dark surface the code keeps its
// edge. The size of the item is the size of the code plus the frame.
Item {
    id: root
    property string qrdata
    property bool render: true // init to false, then set true if render needs delay
    property bool enableToggleText: false  // if true, clicking the QR code shows the encoded text
    property bool isTextState: false    // internal state, if the above is enabled

    signal clicked()

    property var _qrprops: QRIP.getDimensions(qrdata)

    width: frame.width
    height: frame.height

    Rectangle {
        id: frame
        width: r.width + 2 * m3.space8
        height: width
        radius: m3.radiusM
        color: 'white'
    }

    Rectangle {
        id: r
        x: m3.space8
        y: m3.space8
        width: _qrprops.qr_pixelsize
        height: width
        color: 'white'
    }

    Image {
        x: r.x
        y: r.y
        source: qrdata && render ? 'image://qrgen/' + qrdata : ''
        visible: !isTextState

        Rectangle {  // container for logo inside qr code
            visible: root.render && _qrprops.valid
            color: 'white'
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: _qrprops.icon_pixelsize
            height: _qrprops.icon_pixelsize

            Image {
                visible: _qrprops.valid
                source: Qt.resolvedUrl('../../../icons/m3/electrum.png')
                x: 1
                y: 1
                width: parent.width - 2
                height: parent.height - 2
                scale: 0.9
            }
        }
        M3Text {
            visible: !_qrprops.valid
            text: qsTranslate('QRImage', 'Data too big for QR')
            role: 'bodyMedium'
            color: 'black'
            anchors.centerIn: parent
        }
    }

    Label {
        visible: isTextState
        text: qrdata
        wrapMode: Text.WrapAnywhere
        elide: Text.ElideRight
        x: r.x
        y: r.y
        horizontalAlignment: Qt.AlignHCenter
        verticalAlignment: Qt.AlignVCenter
        color: 'black'
        font.family: FixedFont
        font.pixelSize: text.length < 64
            ? m3.textStyle('titleLarge').size
            : m3.textStyle('bodyMedium').size
        width: r.width
        height: r.height
    }

    MouseArea {
        anchors.fill: parent
        onClicked: {
            if (enableToggleText) {
                root.isTextState = !root.isTextState
            } else {
                root.clicked()
            }
        }
    }

    onVisibleChanged: {
        if (root.visible) {
            // set max brightness to make qr code easier to scan
            if (AppController.isMaxBrightnessOnQrDisplayEnabled()) {
                AppController.setMaxScreenBrightness()
            }
        } else {
            AppController.resetScreenBrightness()
        }
    }
}
