import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

Dialog {
    id: wizard
    modal: true

    width: parent.width
    height: parent.height

    property var wizard_data
    property alias pages : pages

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
    function _loadNextComponent(comp, wdata={}) {
        // remove any existing pages after current page
        while (pages.contentChildren[pages.currentIndex+1]) {
            pages.takeItem(pages.currentIndex+1).destroy()
        }

        var page = comp.createObject(pages)
        page.validChanged.connect(function() {
            pages.pagevalid = page.valid
        } )
        page.lastChanged.connect(function() {
            pages.lastpage = page.last
        } )
        Object.assign(page.wizard_data, wdata) // deep copy
        page.ready = true // signal page it can access wizard_data
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

    header: GridLayout {
        columns: 2
        rowSpacing: 0

        Image {
            source: "../../../icons/electrum.png"
            Layout.preferredWidth: constants.iconSizeXLarge
            Layout.preferredHeight: constants.iconSizeXLarge
            Layout.leftMargin: constants.paddingMedium
            Layout.topMargin: constants.paddingMedium
            Layout.bottomMargin: constants.paddingMedium
        }

        Label {
            text: title
            elide: Label.ElideRight
            Layout.fillWidth: true
            topPadding: constants.paddingXLarge
            bottomPadding: constants.paddingXLarge
            font.bold: true
            font.pixelSize: constants.fontSizeMedium
        }

        Rectangle {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingTiny
            Layout.rightMargin: constants.paddingTiny
            height: 1
            color: Qt.rgba(0,0,0,0.5)
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
