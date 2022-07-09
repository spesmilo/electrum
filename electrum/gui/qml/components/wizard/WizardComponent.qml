import QtQuick 2.0

Item {
    signal next
    signal accept
    property var wizard_data : ({})
    property bool valid
    property bool last: false
    property bool ready: false
}
