import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    required property string invoice_key

    width: parent.width
    height: parent.height

    title: qsTr('Paying Lightning Invoice...')

    Item {
        id: s
        state: ''
        states: [
            State {
                name: ''
            },
            State {
                name: 'success'
                PropertyChanges { target: spinner; running: false }
                PropertyChanges { target: helpText; text: qsTr('Paid!') }
                PropertyChanges { target: icon; source: '../../icons/confirmed.png' }
            },
            State {
                name: 'failed'
                PropertyChanges { target: spinner; running: false }
                PropertyChanges { target: helpText; text: qsTr('Payment failed') }
                PropertyChanges { target: errorText; visible: true }
                PropertyChanges { target: icon; source: '../../icons/warning.png' }
            }
        ]
        transitions: [
            Transition {
                from: ''
                to: 'success'
                PropertyAnimation { target: helpText; properties: 'text'; duration: 0}
                NumberAnimation { target: icon; properties: 'opacity'; from: 0; to: 1; duration: 200 }
                NumberAnimation { target: icon; properties: 'scale'; from: 0; to: 1; duration: 500
                    easing.type: Easing.OutBack
                    easing.overshoot: 10
                }
            },
            Transition {
                from: ''
                to: 'failed'
                PropertyAnimation { target: helpText; properties: 'text'; duration: 0}
                NumberAnimation { target: icon; properties: 'opacity'; from: 0; to: 1; duration: 500 }
            }
        ]
    }

    ColumnLayout {
        id: content
        anchors.centerIn: parent
        width: parent.width

        Item {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: constants.iconSizeXXLarge
            Layout.preferredHeight: constants.iconSizeXXLarge

            BusyIndicator {
                id: spinner
                visible: s.state == ''
                width: constants.iconSizeXXLarge
                height: constants.iconSizeXXLarge
            }

            Image {
                id: icon
                width: constants.iconSizeXXLarge
                height: constants.iconSizeXXLarge
            }
        }

        Label {
            id: helpText
            Layout.alignment: Qt.AlignHCenter
            text: qsTr('Paying...')
            font.pixelSize: constants.fontSizeXXLarge
        }

        Label {
            id: errorText
            Layout.preferredWidth: parent.width
            Layout.alignment: Qt.AlignHCenter
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.Wrap
            font.pixelSize: constants.fontSizeLarge
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onPaymentSucceeded(key) {
            if (key != invoice_key) {
                console.log('wrong invoice ' + key + ' != ' + invoice_key)
                return
            }
            console.log('payment succeeded!')
            s.state = 'success'
        }
        function onPaymentFailed(key, reason) {
            if (key != invoice_key) {
                console.log('wrong invoice ' + key + ' != ' + invoice_key)
                return
            }
            console.log('payment failed: ' + reason)
            s.state = 'failed'
            errorText.text = reason
        }
        function onPaymentAuthRejected() {
            dialog.close()
        }
    }
}
