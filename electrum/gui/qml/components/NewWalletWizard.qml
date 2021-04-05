import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

Dialog {
    id: walletwizard

    title: qsTr('New Wallet')
    modal: true

    enter: null // disable transition

    property var wizard_data

    function _setWizardData(wdata) {
        wizard_data = {}
        Object.assign(wizard_data, wdata) // deep copy
        console.log('wizard data is now :' + JSON.stringify(wizard_data))
    }

    // helper function to dynamically load wizard page components
    // and add them to the SwipeView
    // Here we do some manual binding of page.valid -> pages.pagevalid
    // to propagate the state without the binding going stale
    function _loadNextComponent(comp, wdata={}) {
        var page = comp.createObject(pages, {
            'visible': Qt.binding(function() {
                return pages.currentItem === this
            })
        })
        page.validChanged.connect(function() {
            pages.pagevalid = page.valid
        } )
        page.lastChanged.connect(function() {
            pages.lastpage = page.last
        } )
        Object.assign(page.wizard_data, wdata) // deep copy
        pages.pagevalid = page.valid

        return page
    }

    // State transition functions. These functions are called when the 'Next'
    // button is pressed. They take data from the component, add it to the
    // wizard_data object, and depending on the data create the next page
    // in the conversation.

    function walletnameDone(d) {
        console.log('wallet name done')
        wizard_data['wallet_name'] = pages.currentItem.wallet_name
        var page = _loadNextComponent(components.wallettype, wizard_data)
        page.next.connect(function() {wallettypeDone()})
    }

    function wallettypeDone(d) {
        console.log('wallet type done')
        wizard_data['wallet_type'] = pages.currentItem.wallet_type
        var page = _loadNextComponent(components.keystore, wizard_data)
        page.next.connect(function() {keystoretypeDone()})
    }

    function keystoretypeDone(d) {
        console.log('keystore type done')
        wizard_data['keystore_type'] = pages.currentItem.keystore_type
        var page
        switch(wizard_data['keystore_type']) {
        case 'createseed':
            page = _loadNextComponent(components.createseed, wizard_data)
            page.next.connect(function() {createseedDone()})
            break
        case 'haveseed':
            page = _loadNextComponent(components.haveseed, wizard_data)
            page.next.connect(function() {haveseedDone()})
            break
//        case 'masterkey'
//        case 'hardware'
        }
    }

    function createseedDone(d) {
        console.log('create seed done')
        wizard_data['seed'] = pages.currentItem.seed
        var page = _loadNextComponent(components.confirmseed, wizard_data)
        page.next.connect(function() {confirmseedDone()})
    }

    function confirmseedDone(d) {
        console.log('confirm seed done')
        var page = _loadNextComponent(components.walletpassword, wizard_data)
        page.next.connect(function() {walletpasswordDone()})
        page.last = true
    }

    function haveseedDone(d) {
        console.log('have seed done')
        wizard_data['seed'] = pages.currentItem.seed
        var page = _loadNextComponent(components.walletpassword, wizard_data)
        page.next.connect(function() {walletpasswordDone()})
        page.last = true
    }

    function walletpasswordDone(d) {
        console.log('walletpassword done')
        wizard_data['password'] = pages.currentItem.password
        wizard_data['encrypt'] = pages.currentItem.encrypt
        var page = _loadNextComponent(components.walletpassword, wizard_data)
    }


    ColumnLayout {
        anchors.fill: parent

        SwipeView {
            id: pages
            Layout.fillHeight: true
            interactive: false

            function prev() {
                currentIndex = currentIndex - 1
                _setWizardData(pages.contentChildren[currentIndex].wizard_data)
                pages.pagevalid = pages.contentChildren[currentIndex].valid
                pages.contentChildren[currentIndex+1].destroy()
            }

            function next() {
                currentItem.next()
                currentIndex = currentIndex + 1
            }

            function finalize() {
                walletwizard.accept()
            }

            property bool pagevalid: false
            property bool lastpage: false

            Component.onCompleted: {
                _setWizardData({})
                var start = _loadNextComponent(components.walletname)
                start.next.connect(function() {walletnameDone()})
            }

        }

        PageIndicator {
            id: indicator

            Layout.alignment: Qt.AlignHCenter

            count: pages.count
            currentIndex: pages.currentIndex
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            Button {
                visible: pages.currentIndex == 0
                text: qsTr("Cancel")
                onClicked: walletwizard.close()
            }

            Button {
                visible: pages.currentIndex > 0
                text: qsTr('Back')
                onClicked: pages.prev()
            }

            Button {
                text: "Next"
                visible: !pages.lastpage
                enabled: pages.pagevalid
                onClicked: pages.next()
            }

            Button {
                text: "Create"
                visible: pages.lastpage
                enabled: pages.pagevalid
                onClicked: pages.finalize()
            }

        }
    }

    WizardComponents {
        id: components
    }

}

