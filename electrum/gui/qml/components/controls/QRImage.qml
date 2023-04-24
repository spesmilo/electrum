import QtQuick 2.6
import QtQuick.Controls 2.15

Item {
    id: root
    property string qrdata
    property bool render: true // init to false, then set true if render needs delay
    property var qrprops: QRIP.getDimensions(qrdata)

    property bool enable_toggle_text: false  // if true, clicking the QR code shows the encoded text
    property bool is_in_text_state: false    // internal state, if the above is enabled

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
        visible: !is_in_text_state

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

    Label {
        visible: is_in_text_state
        text: qrdata
        wrapMode: Text.WrapAnywhere
        elide: Text.ElideRight
        anchors.centerIn: parent
        horizontalAlignment: Qt.AlignHCenter
        verticalAlignment: Qt.AlignVCenter
        color: 'black'
        width: r.width
        height: r.height
    }

    MouseArea {
        anchors.fill: parent
        onClicked: {
            if (enable_toggle_text) {
                root.is_in_text_state = !root.is_in_text_state
            }
        }
    }

}
