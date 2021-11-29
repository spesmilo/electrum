import QtQuick 2.0

Item {
    signal next
    signal accept
    property var wizard_data : ({})
    property bool valid
    property bool last: false
//    onValidChanged: console.log('valid change in component itself')
//    onWizard_dataChanged: console.log('wizard data changed in ')
}
