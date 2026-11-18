import QtQuick
import QtQuick.Controls

import "controls"

// Settings of the Material 3 GUI as a page of the stack (route app.routes.preferences): the overflow menu item
// "Settings" opens it where no wallet is open (the Wallets root); on the root of a wallet the same item switches
// to the Settings tab instead. The body is the Settings tab
// itself (SettingsTab, asPage: Network and About open above this page, so back returns here); M3Page gives it the
// Material 3 theme, the background and the title of the top app bar.
M3Page {
    id: root
    objectName: 'Preferences'

    title: qsTranslate('WalletMainView', 'Settings')

    SettingsTab {
        anchors.fill: parent
        asPage: true
    }
}
