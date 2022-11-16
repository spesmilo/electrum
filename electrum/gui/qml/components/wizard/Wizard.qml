import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import "../controls"

ElDialog {
    id: wizard
    modal: true
    focus: true

    width: parent.width
    height: parent.height

    title: wizardTitle + (pages.currentItem.title ? ' - ' + pages.currentItem.title : '')
    iconSource: '../../../icons/electrum.png'

    property string wizardTitle

    property var wizard_data
    property alias pages: pages
    property QtObject wiz

    function doClose() {
        if (pages.currentIndex == 0)
            reject()
        else
            pages.prev()
    }

    function _setWizardData(wdata) {
        wizard_data = {}
        Object.assign(wizard_data, wdata) // deep copy
        console.log('wizard data is now :' + JSON.stringify(wizard_data))
    }

    // helper function to dynamically load wizard page components
    // and add them to the SwipeView
    // Here we do some manual binding of page.valid -> pages.pagevalid and
    // page.last -> pages.lastpage to propagate the state without the binding
    // going stale.
    function _loadNextComponent(view, wdata={}) {
        // remove any existing pages after current page
        while (pages.contentChildren[pages.currentIndex+1]) {
            pages.takeItem(pages.currentIndex+1).destroy()
        }

        var url = Qt.resolvedUrl(wiz.viewToComponent(view))
        var comp = Qt.createComponent(url)
        if (comp.status == Component.Error) {
            console.log(comp.errorString())
            return null
        }

        // make a deepcopy of wdata and pass it to the component
        var wdata_copy={}
        Object.assign(wdata_copy, wdata)
        var page = comp.createObject(pages, {wizard_data: wdata_copy})
        page.validChanged.connect(function() {
            pages.pagevalid = page.valid
        } )
        page.lastChanged.connect(function() {
            pages.lastpage = page.last
        } )
        page.next.connect(function() {
            var newview = wiz.submit(page.wizard_data)
            if (newview.view) {
                console.log('next view: ' + newview.view)
                var newpage = _loadNextComponent(newview.view, newview.wizard_data)
            } else {
                console.log('END')
            }
        })
        page.prev.connect(function() {
            var wdata = wiz.prev()
            console.log('prev view data: ' + JSON.stringify(wdata))
        })

        pages.pagevalid = page.valid
        pages.lastpage = page.last

        return page
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        SwipeView {
            id: pages
            Layout.fillWidth: true
            Layout.fillHeight: true
            interactive: false

            clip:true

            function prev() {
                currentItem.prev()
                currentIndex = currentIndex - 1
                _setWizardData(pages.contentChildren[currentIndex].wizard_data)
                pages.pagevalid = pages.contentChildren[currentIndex].valid
                pages.lastpage = pages.contentChildren[currentIndex].last

            }

            function next() {
                currentItem.accept()
                _setWizardData(pages.contentChildren[currentIndex].wizard_data)
                currentItem.next()
                currentIndex = currentIndex + 1
            }

            function finish() {
                currentItem.accept()
                _setWizardData(pages.contentChildren[currentIndex].wizard_data)
                wizard.accept()
            }

            property bool pagevalid: false
            property bool lastpage: false

            Component.onCompleted: {
                _setWizardData({})
            }

        }

        ColumnLayout {
            Layout.alignment: Qt.AlignHCenter | Qt.AlignBottom

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
                    onClicked: wizard.reject()
                }

                Button {
                    visible: pages.currentIndex > 0
                    text: qsTr('Back')
                    onClicked: pages.prev()
                }

                Button {
                    text: qsTr("Next")
                    visible: !pages.lastpage
                    enabled: pages.pagevalid
                    onClicked: pages.next()
                }

                Button {
                    text: qsTr("Finish")
                    visible: pages.lastpage
                    enabled: pages.pagevalid
                    onClicked: pages.finish()
                }

            }
        }
    }

    // make clicking the dialog background move the scope away from textedit fields
    // so the keyboard goes away
    // TODO: here it works on desktop, but not android. hmm.
    MouseArea {
        anchors.fill: parent
        z: -1000
        onClicked: { parkFocus.focus = true }
        FocusScope { id: parkFocus }
    }

}
