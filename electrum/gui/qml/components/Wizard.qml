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
        pages.lastpage = page.last

        return page
    }

    ColumnLayout {
        anchors.fill: parent

        SwipeView {
            id: pages
            Layout.fillWidth: true
            interactive: false

            function prev() {
                currentIndex = currentIndex - 1
                _setWizardData(pages.contentChildren[currentIndex].wizard_data)
                pages.pagevalid = pages.contentChildren[currentIndex].valid
                pages.lastpage = pages.contentChildren[currentIndex].last
                pages.contentChildren[currentIndex+1].destroy()
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

}
