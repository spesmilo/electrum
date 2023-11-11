import QtQuick 2.6
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.0

Rectangle {
    property string password
    property int strength: 0
    property color strengthColor
    property string strengthText

    onPasswordChanged: checkPasswordStrength(password)

    function checkPasswordStrength() {
        var _strength = Daemon.passwordStrength(password)
        var map = {
            0: [constants.colorError, qsTr('Weak')],
            1: [constants.colorAcceptable, qsTr('Medium')],
            2: [constants.colorDone, qsTr('Strong')],
            3: [constants.colorDone, qsTr('Very Strong')]
        }
        strength = password.length ? _strength + 1 : 0
        strengthText = password.length ? map[_strength][1] : ''
        strengthColor = map[_strength][0]
    }

    height: strengthLabel.height
    color: 'transparent'
    border.color: Material.foreground

    Rectangle {
        id: strengthBar
        x: 1
        y: 1
        width: (parent.width - 2) * strength / 4
        height: parent.height - 2
        color: strengthColor
        Label {
            id: strengthLabel
            anchors.centerIn: parent
            text: strengthText
            color: strength <= 2 ? Material.foreground : '#004000'
        }
    }
}
