import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import QtQml

import "controls"

// Crash dialog of the Material 3 GUI (crashDialog in main.qml, opened on AppController.onShowException; M2-MAP
// F-1: a full-screen dialog).
// repeats: components/ExceptionDialog.qml:10-168 @ e6df7e1c8 (the API: crashData; z: 1000, above every other
// dialog, and z: 1001 for the dialogs it opens; _sending disables the content and shows the busy indicator;
// "Show report contents" logs the traceback and opens the report (crashData.reportstring, rich text) in a
// full-screen dialog that destroys itself when closed; the optional description of the user; "Send Bug Report"
// asks "Confirm to send bugreport?" (app.messageDialog, yesno, z 1001) and on Yes calls
// AppController.sendReport(<the description>); "Not Now" closes; the signals of AppController:
// sendingBugreport -> _sending, sendingBugreportSuccess(text) -> the message (rich text, z 1001) and close,
// sendingBugreportFailure(text) -> the error message (rich text, z 1001), the dialog stays open).
// Differences: Material 3 look: the top bar of M3FullScreenDialog (X closes, as "Not Now"), the content scrolls
// and keeps the description field at least 120 high; the report has its own top bar with the title.
// Strings keep the translation context of the classic file (qsTranslate('ExceptionDialog', ...)).
M3FullScreenDialog
{
    id: root

    property var crashData

    property bool _sending: false

    z: 1000  // assure topmost of all other dialogs. note: child popups need even higher!

    title: ''

    Flickable {
        id: flickable
        anchors.fill: parent
        clip: true
        contentHeight: Math.max(height, content.implicitHeight + 2 * m3.space16)
        interactive: height < content.implicitHeight + 2 * m3.space16
        boundsBehavior: Flickable.StopAtBounds
        enabled: !_sending

        ColumnLayout {
            id: content
            readonly property int margin: m3.screenMargin(root.width)
            x: Math.max(margin, (flickable.width - width) / 2)
            y: m3.space16
            width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
            height: flickable.contentHeight - 2 * m3.space16
            spacing: m3.space16

            M3Icon {
                Layout.alignment: Qt.AlignHCenter
                size: 48
                source: Qt.resolvedUrl('../../icons/m3/bug_report.png')
                color: m3.error
            }
            M3Text {
                Layout.fillWidth: true
                role: 'headlineSmall'
                horizontalAlignment: Text.AlignHCenter
                text: qsTranslate('ExceptionDialog', 'Sorry!')
            }

            M3Text {
                Layout.fillWidth: true
                role: 'bodyLarge'
                wrapMode: Text.Wrap
                lineHeightMode: Text.ProportionalHeight
                lineHeight: 1.0
                text: qsTranslate('ExceptionDialog', 'Something went wrong while executing Electrum.')
            }
            M3Text {
                Layout.fillWidth: true
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                wrapMode: Text.Wrap
                lineHeightMode: Text.ProportionalHeight
                lineHeight: 1.0
                text: qsTranslate('ExceptionDialog', 'To help us diagnose and fix the problem, you can send us a bug report that contains useful debug information:')
            }
            M3Button {
                Layout.alignment: Qt.AlignHCenter
                variant: 'outlined'
                text: qsTranslate('ExceptionDialog', 'Show report contents')
                onClicked: {
                    if (crashData.traceback)
                        console.log('traceback: ' + crashData.traceback.stack)
                    var dialog = report.createObject(app, {
                        reportText: crashData.reportstring
                    })
                    dialog.open()
                }
            }
            M3Text {
                Layout.fillWidth: true
                role: 'bodyMedium'
                wrapMode: Text.Wrap
                lineHeightMode: Text.ProportionalHeight
                lineHeight: 1.0
                text: qsTranslate('ExceptionDialog', 'Please briefly describe what led to the error (optional):')
            }
            M3TextArea {
                id: user_text
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.minimumHeight: 120
            }
            M3Text {
                Layout.fillWidth: true
                role: 'bodyMedium'
                wrapMode: Text.Wrap
                text: qsTranslate('ExceptionDialog', 'Do you want to send this report?')
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: m3.space8

                M3Button {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 2
                    variant: 'outlined'
                    size: 56
                    text: qsTranslate('ExceptionDialog', 'Not Now')
                    onClicked: close()
                }
                M3Button {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 3
                    variant: 'filled'
                    size: 56
                    text: qsTranslate('ExceptionDialog', 'Send Bug Report')
                    onClicked: {
                        var dialog = app.messageDialog.createObject(app, {
                            text: qsTranslate('ExceptionDialog', 'Confirm to send bugreport?'),
                            yesno: true,
                            z: 1001  // assure topmost of all other dialogs
                        })
                        dialog.accepted.connect(function() {
                            AppController.sendReport(user_text.text)
                        })
                        dialog.open()
                    }
                }
            }
        }
    }

    BusyIndicator {
        anchors.centerIn: parent
        running: _sending
    }

    Component {
        id: report
        M3FullScreenDialog {
            property string reportText

            z: 1001  // above root
            title: qsTranslate('ExceptionDialog', 'Show report contents')

            Flickable {
                id: reportFlick
                anchors.fill: parent
                clip: true
                contentHeight: reportLabel.implicitHeight + 2 * m3.space16
                interactive: height < contentHeight
                boundsBehavior: Flickable.StopAtBounds

                M3Text {
                    id: reportLabel
                    x: m3.screenMargin(reportFlick.width)
                    y: m3.space16
                    width: reportFlick.width - 2 * x
                    role: 'bodySmall'
                    wrapMode: Text.Wrap
                    lineHeightMode: Text.ProportionalHeight
                    lineHeight: 1.0
                    textFormat: Text.RichText
                    text: reportText
                }

                ScrollIndicator.vertical: ScrollIndicator { }
            }
            onClosed: destroy()
        }
    }

    Connections {
        target: AppController
        function onSendingBugreportSuccess(text) {
            _sending = false
            var dialog = app.messageDialog.createObject(app, {
                text: text,
                richText: true,
                z: 1001  // assure topmost of all other dialogs
            })
            dialog.open()
            close()
        }
        function onSendingBugreportFailure(text) {
            _sending = false
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('ExceptionDialog', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/m3/warning.png'),
                text: text,
                richText: true,
                z: 1001  // assure topmost of all other dialogs
            })
            dialog.open()
        }
        function onSendingBugreport() {
            _sending = true
        }
    }
}
