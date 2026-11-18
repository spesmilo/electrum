import QtQuick

// Routes of the Material 3 GUI: one URL per page that Material 3 code opens on the stack (app.routes, see
// main.qml). Callers never name a page file: they push app.routes.<page> with app.pushPage(url, props) or
// app.pushPageOnRoot(url), which push only a page that loaded (never a null one). The URL is resolved relative to
// components_m3/; there is no classic page behind a route (when a page cannot be opened, app.showScreenError()
// offers the classic interface). The Wallets page is also named in main.qml, by mainStackView.initialItem (the
// type Wallets) and by replaceRoot('Wallets.qml'): both lead to components_m3/Wallets.qml, the file of the route
// `wallets`.
// Layout: one block per owning group, blocks separated by a comment line, so that groups editing their own
// block never touch the same or adjacent lines of another group.
QtObject {
    id: routes

    // --- G1 onboarding: wallets ---
    property url wallets: Qt.resolvedUrl('Wallets.qml')

    // --- G2 receiving: invoices and requests ---
    property url invoices: Qt.resolvedUrl('InvoicesPage.qml')
    property url receiveRequests: Qt.resolvedUrl('RequestsPage.qml')

    // --- G3 transactions: details ---
    property url txDetails: Qt.resolvedUrl('TxDetailsPage.qml')
    property url lightningPaymentDetails: Qt.resolvedUrl('LightningPaymentPage.qml')

    // --- G5 wallet and addresses ---
    property url walletDetails: Qt.resolvedUrl('WalletDetailsPage.qml')
    property url addresses: Qt.resolvedUrl('AddressesPage.qml')
    property url addressDetails: Qt.resolvedUrl('AddressDetailsPage.qml')
    property url addressHistory: Qt.resolvedUrl('AddressHistoryPage.qml')
    property url balanceDetails: Qt.resolvedUrl('BalanceDetailsPage.qml')

    // --- G6 channels ---
    property url channelDetails: Qt.resolvedUrl('ChannelDetailsPage.qml')

    // --- G7 network and about ---
    property url networkOverview: Qt.resolvedUrl('NetworkPage.qml')
    property url about: Qt.resolvedUrl('AboutPage.qml')
    property url preferences: Qt.resolvedUrl('SettingsPage.qml')

    // --- end of routes ---
}
