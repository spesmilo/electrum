import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "wizard"

Item {
    property Component walletname: Component {
        WCWalletName {}
    }

    property Component wallettype: Component {
        WCWalletType {}
    }

    property Component keystore: Component {
        WCKeystoreType {}
    }

    property Component createseed: Component {
        WCCreateSeed {}
    }

    property Component haveseed: Component {
        WCHaveSeed {}
    }

    property Component confirmseed: Component {
        WCConfirmSeed {}
    }

    property Component bip39refine: Component {
        WCBIP39Refine {}
    }

    property Component walletpassword: Component {
        WCWalletPassword {}
    }


}
