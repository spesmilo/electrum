import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "wizard"

Wizard {
    id: walletwizard

    title: qsTr('New Wallet')

    signal walletCreated

    property alias path: walletdb.path

    // State transition functions. These functions are called when the 'Next'
    // button is pressed. Depending on the data create the next page
    // in the conversation.

    function walletnameDone(d) {
        console.log('wallet name done')
        var page = _loadNextComponent(components.wallettype, wizard_data)
        page.next.connect(function() {wallettypeDone()})
    }

    function wallettypeDone(d) {
        console.log('wallet type done')
        var page = _loadNextComponent(components.keystore, wizard_data)
        page.next.connect(function() {keystoretypeDone()})
    }

    function keystoretypeDone(d) {
        console.log('keystore type done')
        var page
        switch(wizard_data['keystore_type']) {
        case 'createseed':
            page = _loadNextComponent(components.createseed, wizard_data)
            page.next.connect(function() {createseedDone()})
            break
        case 'haveseed':
            page = _loadNextComponent(components.haveseed, wizard_data)
            page.next.connect(function() {haveseedDone()})
            if (wizard_data['seed_type'] != 'bip39' && Daemon.singlePasswordEnabled)
                page.last = true
            break
        case 'masterkey':
            page = _loadNextComponent(components.havemasterkey, wizard_data)
            page.next.connect(function() {havemasterkeyDone()})
            if (Daemon.singlePasswordEnabled)
                page.last = true
            break
        }
    }

    function createseedDone(d) {
        console.log('create seed done')
        var page = _loadNextComponent(components.confirmseed, wizard_data)
        if (Daemon.singlePasswordEnabled)
            page.last = true
        else
            page.next.connect(function() {confirmseedDone()})
    }

    function confirmseedDone(d) {
        console.log('confirm seed done')
        var page = _loadNextComponent(components.walletpassword, wizard_data)
        page.last = true
    }

    function haveseedDone(d) {
        console.log('have seed done')
        if (wizard_data['seed_type'] == 'bip39') {
            var page = _loadNextComponent(components.bip39refine, wizard_data)
            if (Daemon.singlePasswordEnabled)
                page.last = true
            else
                page.next.connect(function() {bip39refineDone()})
        } else {
            var page = _loadNextComponent(components.walletpassword, wizard_data)
            page.last = true
        }
    }

    function bip39refineDone(d) {
        console.log('bip39 refine done')
        var page = _loadNextComponent(components.walletpassword, wizard_data)
        page.last = true
    }

    function havemasterkeyDone(d) {
        console.log('have master key done')
        var page = _loadNextComponent(components.walletpassword, wizard_data)
        page.last = true
    }

    Item {
        id: components
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

        property Component havemasterkey: Component {
            WCHaveMasterKey {}
        }

        property Component walletpassword: Component {
            WCWalletPassword {}
        }
    }


    Component.onCompleted: {
        _setWizardData({})
        var start = _loadNextComponent(components.walletname)
        start.next.connect(function() {walletnameDone()})
    }

    onAccepted: {
        console.log('Finished new wallet wizard')
        walletdb.create_storage(wizard_data, Daemon.singlePasswordEnabled, Daemon.singlePassword)
    }

    WalletDB {
        id: walletdb
        onCreateSuccess: walletwizard.walletCreated()
    }
}

