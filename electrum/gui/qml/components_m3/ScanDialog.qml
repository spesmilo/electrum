import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import org.electrum

import "controls"

// QR scan dialog of the Material 3 GUI (app.scanDialog; a full-screen dialog, the callers keep the
// classic API).
// repeats: components/ScanDialog.qml:8-63 (the API: hint, error, foundText(data), open(), close();
// the scanner stops on aboutToHide; the own doClose() (the Android back button) stops the scanner and rejects
// later (Qt.callLater(doReject)); the window is secure (no screenshots, no screen recording of the camera image)
// while the dialog is visible; the dialog destroys itself when closed (the factory does not)).
// Differences: Material 3 look: the top bar of M3FullScreenDialog with the close button (X -> doReject(), as the
// classic Cancel button at the bottom) and a title; the viewfinder is M3QRScan.
// Strings keep the translation context of the classic file (qsTranslate('ScanDialog', ...)).
M3FullScreenDialog {
    id: scanDialog

    property string error
    property string hint: qsTranslate('ScanDialog', 'Scan a QR code.')

    signal foundText(data: string)

    title: qsTr('Scan QR code')

    onAboutToHide: qrscan.stop()

    function doClose() {
        qrscan.stop()
        Qt.callLater(doReject)
    }

    M3QRScan {
        id: qrscan
        anchors.fill: parent
        hint: scanDialog.hint
        onFoundText: (data) => {
            scanDialog.foundText(data)
        }
    }

    // Keep the camera preview out of screenshots and screen recordings.
    Binding {
        target: AppController
        property: 'secureWindow'
        when: scanDialog.visible  // enables stacking multiple secureWindow dialogs
        value: true
    }

    onClosed: destroy()
}
