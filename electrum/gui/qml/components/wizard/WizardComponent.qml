import QtQuick 2.0

Item {
    signal next
    signal prev
    signal accept
    property var wizard_data : ({})
    property bool valid
    property bool last: false
    property bool ready: false

    onAccept: {
        apply()
    }

    function apply() { }
    function checkIsLast() {
        apply()
        last = wizard.wiz.isLast(wizard_data)
    }

    Component.onCompleted: {
        checkIsLast()
    }

}
