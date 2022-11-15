import QtQuick 2.0

Item {
    signal next
    signal prev
    signal accept
    property var wizard_data : ({})
    property bool valid
    property bool last: false
    property string title: ''

    onAccept: {
        apply()
    }

    // override this in descendants to put data from the view in wizard_data
    function apply() { }

    function checkIsLast() {
        apply()
        last = wizard.wiz.isLast(wizard_data)
    }

    Component.onCompleted: {
        // NOTE: Use Qt.callLater to execute checkIsLast(), and by extension apply(),
        // otherwise Component.onCompleted handler in descendants is processed
        // _after_ apply() is called, which may lead to setting the wrong
        // wizard_data keys if apply() depends on variables set in descendant
        // Component.onCompleted handler.
        Qt.callLater(checkIsLast)
    }

}
