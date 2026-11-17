import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

// Base of a Material 3 wizard page (DESIGN-M2-onboarding.md 2.1, 3.0).
// repeats: components/wizard/WizardComponent.qml:5-52 @ e6df7e1c8 (the signals, the properties wizard_data, valid,
// last, wizard_title, title, securePage, onAccept -> apply(), checkIsLast() via wizard.wiz.isLast, the
// Component.onCompleted with Qt.callLater and the focus, the tap on the empty page that takes the focus).
// Differences: the content sits in a centered column of at most m3.maxContentWidth with the screen margins
// (16 / 24), the background is transparent (the wizard popup draws m3.surface), and ensureVisible(flick, item)
// scrolls a Flickable of the page so that `item` is visible (Qt does not do it when the keyboard shrinks the page).
Pane {
    id: root
    signal next
    signal finish
    signal prev
    signal accept
    property var wizard_data : ({})
    property bool valid
    property bool last: false
    property string wizard_title: ''
    property string title: ''
    property bool securePage: false

    leftPadding: Math.max(m3.screenMargin(width), (width - m3.maxContentWidth) / 2)
    rightPadding: leftPadding
    topPadding: m3.space8
    bottomPadding: 0

    background: Item {}

    // the tap handler belongs to the Pane itself: in `background` it never sees the press (M3Card.qml)
    data: [
        TapHandler {
            onTapped: root.forceActiveFocus()
        }
    ]

    onAccept: {
        apply()
    }

    // override this in descendants to put data from the view in wizard_data
    function apply() { }

    function checkIsLast() {
        apply()
        last = wizard.wiz.isLast(wizard_data)
    }

    // scroll `flick` so that the whole of `item` (a descendant of its content) is visible, bottom first
    function ensureVisible(flick, item) {
        if (!flick || !item || !item.visible)
            return
        var p = item.mapToItem(flick.contentItem, 0, 0)
        var bottom = p.y + item.height + m3.space8
        if (bottom > flick.contentY + flick.height)
            flick.contentY = Math.min(Math.max(0, flick.contentHeight - flick.height), bottom - flick.height)
        else if (p.y < flick.contentY)
            flick.contentY = Math.max(0, p.y - m3.space8)
    }

    Component.onCompleted: {
        // NOTE: Use Qt.callLater to execute checkIsLast(), and by extension apply(),
        // otherwise Component.onCompleted handler in descendants is processed
        // _after_ apply() is called, which may lead to setting the wrong
        // wizard_data keys if apply() depends on variables set in descendant
        // Component.onCompleted handler.
        Qt.callLater(checkIsLast)

        // move focus to root of WizardComponent, otherwise Android back button
        // might be missed in Wizard root Item.
        root.forceActiveFocus()
    }

}
