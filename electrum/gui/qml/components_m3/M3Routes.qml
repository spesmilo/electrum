import QtQuick

// Routes of the Material 3 GUI: one URL per page that Material 3 code opens on the stack (app.routes, see
// main.qml). Callers never name a page file: they push app.routes.<page> with app.pushPage(url, props) or
// app.pushPageOnRoot(url), which push only a page that loaded (never a null one). The group that moves a
// page to Material 3 changes the first line of its route (the URL, resolved relative to components_m3/); the
// second line, <page>Classic, is the classic page that app.loadPage() opens when the Material 3 one cannot be
// loaded (fallback for the time of the M2 waves; removed together with it, M2-MAP F-14). Exception: the
// classic Wallets page is also named in main.qml, by mainStackView.initialItem (Classic.Wallets) and
// mainStackView._classicRoots (replaceRoot('Wallets.qml')): the group of `wallets` changes those too.
// Constraint: two routes must not lead to the same Material 3 file: the fallback is looked up by the URL
// (classicFor), so both routes would fall back to the classic page of the first one.
// Layout: one block per owning group, blocks separated by a comment line, so that groups editing their own
// block never touch the same or adjacent lines of another group.
QtObject {
    id: routes

    // the classic URL of the route `url` (one of the properties below), or '' when `url` is no route
    function classicFor(url) {
        var s = String(url)
        for (var name in routes) {
            if (name.length > 7 && name.slice(-7) === 'Classic') {
                var route = name.slice(0, -7)
                if (route in routes && String(routes[route]) === s)
                    return routes[name]
            }
        }
        return ''
    }

    // --- G1 onboarding: wallets ---
    property url wallets: Qt.resolvedUrl('../components/Wallets.qml')
    property url walletsClassic: Qt.resolvedUrl('../components/Wallets.qml')

    // --- G2 receiving: invoices and requests ---
    property url invoices: Qt.resolvedUrl('../components/Invoices.qml')
    property url invoicesClassic: Qt.resolvedUrl('../components/Invoices.qml')
    property url receiveRequests: Qt.resolvedUrl('../components/ReceiveRequests.qml')
    property url receiveRequestsClassic: Qt.resolvedUrl('../components/ReceiveRequests.qml')

    // --- G3 transactions: details ---
    property url txDetails: Qt.resolvedUrl('../components/TxDetails.qml')
    property url txDetailsClassic: Qt.resolvedUrl('../components/TxDetails.qml')
    property url lightningPaymentDetails: Qt.resolvedUrl('../components/LightningPaymentDetails.qml')
    property url lightningPaymentDetailsClassic: Qt.resolvedUrl('../components/LightningPaymentDetails.qml')

    // --- G5 wallet and addresses ---
    property url walletDetails: Qt.resolvedUrl('../components/WalletDetails.qml')
    property url walletDetailsClassic: Qt.resolvedUrl('../components/WalletDetails.qml')
    property url addresses: Qt.resolvedUrl('../components/Addresses.qml')
    property url addressesClassic: Qt.resolvedUrl('../components/Addresses.qml')
    property url addressDetails: Qt.resolvedUrl('../components/AddressDetails.qml')
    property url addressDetailsClassic: Qt.resolvedUrl('../components/AddressDetails.qml')
    property url addressHistory: Qt.resolvedUrl('../components/AddressHistory.qml')
    property url addressHistoryClassic: Qt.resolvedUrl('../components/AddressHistory.qml')
    property url balanceDetails: Qt.resolvedUrl('../components/BalanceDetails.qml')
    property url balanceDetailsClassic: Qt.resolvedUrl('../components/BalanceDetails.qml')

    // --- G6 channels ---
    property url channels: Qt.resolvedUrl('../components/Channels.qml')
    property url channelsClassic: Qt.resolvedUrl('../components/Channels.qml')
    property url channelDetails: Qt.resolvedUrl('../components/ChannelDetails.qml')
    property url channelDetailsClassic: Qt.resolvedUrl('../components/ChannelDetails.qml')

    // --- G7 network and about ---
    property url networkOverview: Qt.resolvedUrl('../components/NetworkOverview.qml')
    property url networkOverviewClassic: Qt.resolvedUrl('../components/NetworkOverview.qml')
    property url about: Qt.resolvedUrl('../components/About.qml')
    property url aboutClassic: Qt.resolvedUrl('../components/About.qml')
    property url preferences: Qt.resolvedUrl('../components/Preferences.qml')
    property url preferencesClassic: Qt.resolvedUrl('../components/Preferences.qml')

    // --- end of routes ---
}
