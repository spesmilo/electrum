import QtQuick
import QtQuick.Controls

Item {
    id: root
    property string qrdata
    property bool render: true // init to false, then set true if render needs delay
    property bool enableToggleText: false  // if true, clicking the QR code shows the encoded text
    property bool isTextState: false    // internal state, if the above is enabled

    property var _qrprops: QRIP.getDimensions(qrdata)

    width: r.width
    height: r.height

    Rectangle {
        id: r
        width: _qrprops.modules * _qrprops.box_size
        height: width
        color: 'white'
    }

    Image {
        source: qrdata && render ? 'image://qrgen/' + qrdata : ''
        visible: !isTextState

        Rectangle {  // container for logo inside qr code
            visible: root.render && _qrprops.valid
            color: 'white'
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: _qrprops.icon_modules * _qrprops.box_size
            height: _qrprops.icon_modules * _qrprops.box_size

            Image {
                visible: _qrprops.valid
                source: '../../../icons/electrum.png'
                x: 1
                y: 1
                width: parent.width - 2
                height: parent.height - 2
                scale: 0.9
            }
        }
        Label {
            visible: !_qrprops.valid
            text: qsTr('Data too big for QR')
            anchors.centerIn: parent
        }
    }

    Label {
        visible: isTextState
        text: qrdata
        wrapMode: Text.WrapAnywhere
        elide: Text.ElideRight
        anchors.centerIn: parent
        horizontalAlignment: Qt.AlignHCenter
        verticalAlignment: Qt.AlignVCenter
        color: 'black'
        font.family: FixedFont
        font.pixelSize: text.length < 64
            ? constants.fontSizeXLarge
            : constants.fontSizeMedium
        width: r.width
        height: r.height
    }

    MouseArea {
        anchors.fill: parent
        onClicked: {
            if (enableToggleText) {
                root.isTextState = !root.isTextState
            }
        }
    }

    onVisibleChanged: {
        if (root.visible) {
            // set max brightness to make qr code easier to scan
            AppController.setMaxScreenBrightness()
        } else {
            AppController.resetScreenBrightness()
        }
    }

}
