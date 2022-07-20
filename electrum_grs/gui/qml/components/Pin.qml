import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Dialog {
    id: root

    title: qsTr('PIN')

    width: parent.width * 2/3
    height: parent.height * 1/3

    x: (parent.width - width) / 2
    y: (parent.height - height) / 2

    modal: true
    parent: Overlay.overlay
    Overlay.modal: Rectangle {
        color: canCancel ? "#aa000000" : "#ff000000"
    }

    focus: true

    standardButtons: canCancel ? Dialog.Cancel : 0
    closePolicy: canCancel ? Popup.CloseOnEscape | Popup.CloseOnPressOutside : Popup.NoAutoClose

    property bool canCancel: true

    property string mode // [check, enter, change]
    property string pincode // old one passed in when change, new one passed out

    property int _phase: mode == 'enter' ? 1 : 0 // 0 = existing pin, 1 = new pin, 2 = re-enter new pin
    property string _pin

    function submit() {
        if (_phase == 0) {
            if (pin.text == pincode) {
                pin.text = ''
                if (mode == 'check')
                    accepted()
                else
                    _phase = 1
                return
            }
        }
        if (_phase == 1) {
            _pin = pin.text
            pin.text = ''
            _phase = 2
            return
        }
        if (_phase == 2) {
            if (_pin == pin.text) {
                pincode = pin.text
                accepted()
            }
            return
        }
    }

    header: GridLayout {
        columns: 2
        rowSpacing: 0

        Image {
            source: "../../icons/lock.png"
            Layout.preferredWidth: constants.iconSizeXLarge
            Layout.preferredHeight: constants.iconSizeXLarge
            Layout.leftMargin: constants.paddingMedium
            Layout.topMargin: constants.paddingMedium
            Layout.bottomMargin: constants.paddingMedium
        }

        Label {
            text: title
            elide: Label.ElideRight
            Layout.fillWidth: true
            topPadding: constants.paddingXLarge
            bottomPadding: constants.paddingXLarge
            font.bold: true
            font.pixelSize: constants.fontSizeMedium
        }

        Rectangle {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingXXSmall
            Layout.rightMargin: constants.paddingXXSmall
            height: 1
            color: Qt.rgba(0,0,0,0.5)
        }
    }

    ColumnLayout {
        width: parent.width
        height: parent.height

        Label {
            text: [qsTr('Enter PIN'), qsTr('Enter New PIN'), qsTr('Re-enter New PIN')][_phase]
            font.pixelSize: constants.fontSizeXXLarge
            Layout.alignment: Qt.AlignHCenter
        }

        TextField {
            id: pin
            Layout.preferredWidth: root.width *2/3
            Layout.alignment: Qt.AlignHCenter
            font.pixelSize: constants.fontSizeXXLarge
            maximumLength: 6
            inputMethodHints: Qt.ImhDigitsOnly
            echoMode: TextInput.Password
            focus: true
            onTextChanged: {
                if (text.length == 6) {
                    submit()
                }
            }
        }

        Item { Layout.fillHeight: true; Layout.preferredWidth: 1 }
    }

}
