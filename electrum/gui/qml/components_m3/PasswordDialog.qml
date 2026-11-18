import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// Password dialog of the Material 3 GUI (app.passwordDialog; M2-MAP F-2: an M3Dialog).
// repeats: components/PasswordDialog.qml:8-119 @ e6df7e1c8 (the API: title, confirmPassword, infotext,
// errorMessage, passwordEntered(password), clearPassword(); _closing: Ok is ignored once closing has started,
// set on aboutToShow / aboutToHide; the second field only with confirmPassword, without its own reveal button and
// with the echo mode of the first; the strength indicator with confirmPassword; Ok enabled with confirmPassword
// only when the password has at least 6 characters and both fields match, otherwise always; Ok emits
// passwordEntered with the first field and does not close: the caller closes the dialog or sets errorMessage).
// Differences: Material 3 look (M3PasswordField, M3PasswordStrength, M3InfoText); a Cancel text button next to
// Ok, which does what the Android back button does (doClose() -> doReject(), the `rejected` signal; shown only
// when allowClose; ignored once closing has started, as Ok); the content scrolls when the keyboard leaves too
// little height, and what matters is scrolled into view: the field with the focus, or, after a refused password
// until a character is typed again, the error line.
// Strings keep the translation context of the classic file (qsTranslate('PasswordDialog', ...)).
M3Dialog {
    id: passworddialog

    title: qsTranslate('PasswordDialog', 'Enter Password')
    iconSource: Qt.resolvedUrl('../../icons/m3/lock.png')

    property bool confirmPassword: false
    property string infotext
    property string errorMessage

    // Ignore Ok (and the Material 3 Cancel) once closing has started.
    property bool _closing: false

    signal passwordEntered(string password)

    onAboutToShow: _closing = false
    onAboutToHide: _closing = true

    // the dialog never grows past the free zone (keyboard included): the content scrolls instead
    // (centered: the same margin above and below, clear of the status bar and of the navigation bar; while the
    // keyboard is open the navigation bar is under it and the margin is smaller, the height is short then)
    height: Math.min(implicitHeight, parent
        ? parent.height - 2 * (app.keyboardFreeZone.state != 'visible'
            ? m3.space24 + Math.max(app.statusBarHeight, app.navigationBarHeight)
            : m3.space8 + app.statusBarHeight)
        : implicitHeight)

    contentItem: Flickable {
        id: flick
        implicitHeight: form.implicitHeight
        contentHeight: form.implicitHeight
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        // the keyboard shrinks the dialog after the field got the focus, the error line grows the content (laid out
        // after the error was set): keep in view what matters now
        onHeightChanged: passworddialog._keepInView()
        onContentHeightChanged: passworddialog._keepInView()

        ScrollIndicator.vertical: ScrollIndicator { }

        ColumnLayout {
            id: form
            width: flick.width
            spacing: m3.space12

            M3InfoText {
                visible: infotext
                text: infotext
                Layout.fillWidth: true
                compact: true
            }

            M3PasswordField {
                id: pw_1
                Layout.fillWidth: true
                label: qsTranslate('PasswordDialog', 'Password')
                onTextChanged: if (text !== '') passworddialog._errorPending = false
            }

            M3PasswordField {
                id: pw_2
                Layout.fillWidth: true
                visible: confirmPassword
                showReveal: false
                echoMode: pw_1.echoMode
                label: qsTranslate('PasswordDialog', 'Password (again)')
                onTextChanged: if (text !== '') passworddialog._errorPending = false
            }

            ColumnLayout {
                Layout.fillWidth: true
                visible: confirmPassword
                spacing: m3.space4

                M3Text {
                    role: 'labelMedium'
                    color: m3.surfaceVariantOn
                    text: qsTranslate('PasswordDialog', 'Strength')
                }

                M3PasswordStrength {
                    Layout.fillWidth: true
                    password: pw_1.text
                }
            }

            // the last row of the form: its bottom is the bottom of the content (_keepInView)
            M3Text {
                id: errorLine
                Layout.fillWidth: true
                visible: errorMessage
                role: 'bodyMedium'
                color: m3.error
                wrapMode: Text.Wrap
                lineHeightMode: Text.ProportionalHeight
                lineHeight: 1.0
                text: errorMessage
            }
        }
    }

    buttons: [
        M3Button {
            variant: 'text'
            text: qsTranslate('PasswordDialog', 'Ok')
            enabled: confirmPassword ? pw_1.text.length >= 6 && pw_1.text == pw_2.text : true
            onClicked: {
                if (passworddialog._closing)
                    return
                passwordEntered(pw_1.text)
            }
        },
        M3Button {
            variant: 'text'
            text: qsTr('Cancel')
            visible: passworddialog.allowClose
            onClicked: {
                if (passworddialog._closing)
                    return
                passworddialog.doClose()
            }
        }
    ]

    function clearPassword() {
        pw_1.text = ""
        pw_2.text = ""
        // with an error already shown this is a refusal repeated with the same message (errorMessage does not change)
        if (errorMessage !== '')
            _errorPending = true
    }

    // what a shrunk dialog shows: the error line from a refusal until a character is typed in either field, otherwise
    // the field with the focus. A refusal sets _errorPending: errorMessage becomes non-empty, or clearPassword() is
    // called while it is non-empty (main.qml handleManualAuth clears the fields, then sets the error; the change of
    // password in WalletDetailsPage.qml sets the error, then clears the fields; a repeated refusal leaves errorMessage
    // as it is). The first non-empty text in either field clears it (onTextChanged, whatever the way of input);
    // erasing the fields back to empty does not set it again.
    property bool _errorPending: false
    onErrorMessageChanged: if (errorMessage !== '') _errorPending = true
    readonly property bool _errorInView: _errorPending && errorMessage !== ''
    on_ErrorInViewChanged: _keepInView()

    // the error line whole, its bottom at the bottom of the content window (its top, if it is taller), else the
    // field with the focus
    function _keepInView() {
        if (!_errorInView) {
            _showFocusedField()
            return
        }
        if (flick.height <= 0)
            return
        flick.contentY = Math.max(0, Math.min(flick.contentHeight - errorLine.implicitHeight,
            flick.contentHeight - flick.height))
    }

    // scroll the form so that the field with the focus is seen whole (Flickable does not follow the focus)
    function _showFocusedField() {
        var field = pw_2.visible && pw_2.field.activeFocus ? pw_2.field : pw_1.field.activeFocus ? pw_1.field : null
        if (!field || flick.height <= 0)
            return
        var top = field.mapToItem(form, 0, 0).y
        var bottom = top + field.height
        // scrolling up: the floating label of the outlined field reaches above the field, keep (up to) the gap over
        // it in view while the field stays whole
        if (top < flick.contentY)
            flick.contentY = Math.max(0, Math.min(top, Math.max(top - m3.space12, bottom - flick.height)))
        else if (bottom > flick.contentY + flick.height)
            flick.contentY = Math.min(bottom - flick.height, Math.max(0, flick.contentHeight - flick.height))
    }

    // a field that gets the focus (a tap, Tab) is scrolled into view, also while the error line is shown; a change of
    // the height that comes after it (the keyboard opening after the tap) brings the error line back into view while
    // no character has been typed since the refusal (_keepInView)
    Connections {
        target: pw_1.field
        function onActiveFocusChanged() { passworddialog._showFocusedField() }
    }
    Connections {
        target: pw_2.field
        function onActiveFocusChanged() { passworddialog._showFocusedField() }
    }
}
