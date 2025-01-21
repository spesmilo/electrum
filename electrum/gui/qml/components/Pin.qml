import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: root

    property bool canCancel: true
    property string mode // [check, enter, change]
    property string pincode // old one passed in when change, new one passed out
    property bool checkError: false
    property string authMessage
    property int _phase: mode == 'enter' ? 1 : 0 // 0 = existing pin, 1 = new pin, 2 = re-enter new pin
    property string _pin

    title: authMessage ? authMessage : qsTr('PIN')
    iconSource: Qt.resolvedUrl('../../icons/lock.png')
    width: parent.width * 3/4
    z: 1000
    focus: true
    closePolicy: canCancel ? Popup.CloseOnEscape | Popup.CloseOnPressOutside : Popup.NoAutoClose
    allowClose: canCancel

    anchors.centerIn: parent

    Overlay.modal: Rectangle {
        color: canCancel ? "#aa000000" : "#ff000000"
    }

    function submit() {
        if (_phase == 0) {
            if (pin.text == pincode) {
                pin.text = ''
                if (mode == 'check')
                    accepted()
                else
                    _phase = 1
            } else {
                pin.text = ''
                checkError = true
            }
        } else if (_phase == 1) {
            _pin = pin.text
            pin.text = ''
            _phase = 2
        } else if (_phase == 2) {
            if (_pin == pin.text) {
                pincode = pin.text
                accepted()
            } else {
                pin.text = ''
                checkError = true
            }
        }
    }

    onAccepted: result = Dialog.Accepted
    onRejected: result = Dialog.Rejected
    onClosed: {
        if (!root.result) {
            root.reject() // make sure we reject the authed fn()
        }
    }

    ColumnLayout {
        width: parent.width

        Label {
            text: [qsTr('Enter PIN'), qsTr('Enter New PIN'), qsTr('Re-enter New PIN')][_phase]
            font.pixelSize: constants.fontSizeXLarge
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }

        TextField {
            id: pin
            Layout.preferredWidth: fontMetrics.advanceWidth(passwordCharacter) * 6 + pin.leftPadding + pin.rightPadding
            Layout.preferredHeight: fontMetrics.height + pin.topPadding + pin.bottomPadding
            Layout.alignment: Qt.AlignHCenter
            font.pixelSize: constants.fontSizeXXLarge
            maximumLength: 6
            inputMethodHints: Qt.ImhDigitsOnly

            echoMode: TextInput.Password
            focus: true
            onTextChanged: {
                checkError = false
                if (text.length == 6) {
                    submit()
                }
            }
        }

        Label {
            opacity: checkError ? 1 : 0
            text: _phase == 0 ? qsTr('Wrong PIN') : qsTr('PIN doesn\'t match')
            color: constants.colorError
            Layout.alignment: Qt.AlignHCenter
        }
    }

    FontMetrics {
        id: fontMetrics
        font: pin.font
    }

}
