import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "../controls"

// Material 3 wizard frame (DESIGN-M2-onboarding.md 2.1-2.4, DESIGN-M2.md 3-4): a full-screen popup in
// app.keyboardFreeZone (it shrinks above the on-screen keyboard, so the main button stays visible), with the same
// contract as the classic wizard for Python, the wrappers, the pages and main.qml.
// repeats: components/wizard/Wizard.qml:10-161, 182-199 @ e6df7e1c8 (id: wizard, focus, closePolicy, wizardTitle,
// wizard_data, pages, wiz, finishButtonText, doClose(), _setWizardData(), _loadNextComponent() but for the url of
// the page, the root layout with the Android back key, the SwipeView with prev/next/finish/pagevalid/lastpage,
// the secureWindow Binding, Next/Finish: visible by lastpage, enabled by pagevalid).
// Differences: the top bar has the back arrow (pages.prev(), as the classic "Back") and, on the first page, the
// close button (doReject(), as the classic "Cancel") unless `canCancel` is false (wizards whose cancel quits the
// app: the Android back key is the way out, as in the classic); `topBarVisible: false` hides the bar and puts
// "Cancel" in the bottom bar instead (terms of use); one filled main button at the bottom right; a tap on it in
// the first 300 ms after a page change is ignored (no double tap through a page); a page that cannot be opened (no
// Material 3 version: a new upstream page, a plugin page not in _m3PluginPages; a broken file; a page that cannot
// be created) is not shown: the error goes to the log and app.showScreenError() offers the classic interface (no
// classic page is shown in its place).
M3FullScreenDialog {
    id: wizard
    focus: true

    title: _pageTitle

    // android back button triggers close() on Popups. Disabling close here,
    // we handle that via Keys.onReleased event handler in the root layout.
    closePolicy: Popup.NoAutoClose

    property string wizardTitle

    property var wizard_data
    property alias pages: pages
    property QtObject wiz
    property alias finishButtonText: finishButton.text

    // M3: the close button on the first page (false: the wizard cannot be cancelled from the screen)
    property bool canCancel: true
    // M3: the top bar (false: no bar, "Cancel" in the bottom bar on the first page)
    property bool topBarVisible: true

    readonly property Item _page: pages.currentItem
    readonly property string _pageTitle: _page
        ? (_page.title ? _page.title : (_page.wizard_title ? _page.wizard_title : wizardTitle))
        : wizardTitle
    readonly property string _pageSubtitle: _page && _page.title ? wizardTitle : ''

    // the pages that a plugin has in Material 3: electrum/plugins/<plugin>/qml_m3/<page>.qml (M2-MAP F-11)
    readonly property var _m3PluginPages: ({
        'trustedcoin': ['Disclaimer', 'ChooseSeed', 'KeepDisable', 'Terms', 'ShowConfirmOTP']
    })

    // the bars are drawn by the header and the footer below; the content has no padding of its own
    topPadding: topBarVisible ? 0 : app.statusBarHeight
    bottomPadding: 0

    function doClose() {
        if (pages.currentIndex == 0)
            reject()
        else
            pages.prev()
    }

    function _setWizardData(wdata) {
        wizard_data = {}
        Object.assign(wizard_data, wdata) // deep copy
        // console.log('wizard data is now :' + JSON.stringify(wizard_data))
    }

    // M3: the url of the page for the name given by Python: the Material 3 page next to this file (for a plugin
    // page, the one in the qml_m3 directory of the plugin); '' when there is none.
    // A plugin page is any name with /plugins/ in it (DESIGN-M2.md finding 11): only the form
    // .../plugins/<plugin>/qml/<page>.qml listed in _m3PluginPages has a Material 3 page; any other plugin name (not
    // in the table, or of another form, e.g. qml/wizard/<page>.qml) has none, never loaded as if it were one.
    function _pageUrl(name) {
        var plugin = name.match(/\/plugins\/([^\/]+)\/qml\/([^\/]+)\.qml$/)
        if (plugin) {
            var known = _m3PluginPages[plugin[1]]
            return known && known.indexOf(plugin[2]) >= 0
                ? Qt.resolvedUrl(name.replace('/plugins/' + plugin[1] + '/qml/', '/plugins/' + plugin[1] + '/qml_m3/'))
                : ''
        }
        return name.indexOf('/plugins/') >= 0 ? '' : Qt.resolvedUrl(name)
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

        // M3: a page that cannot be opened: the log and app.showScreenError(), the wizard stays on its page
        var name = wiz.viewToComponent(view)
        var url = _pageUrl(name)
        if (url == '') {
            console.warn('M3 wizard: no Material 3 page for ' + name)
            app.showScreenError()
            return null
        }
        var comp = Qt.createComponent(url)
        if (comp.status == Component.Error) {
            console.log(comp.errorString())
            app.showScreenError()
            return null
        }

        // make a deepcopy of wdata and pass it to the component
        var wdata_copy={}
        Object.assign(wdata_copy, wdata)
        var page = comp.createObject(pages, {wizard_data: wdata_copy})
        if (!page) {
            console.warn('M3 wizard: cannot create the page ' + url)
            app.showScreenError()
            return null
        }
        page.validChanged.connect(function() {
            if (page != pages.currentItem)
                return
            pages.pagevalid = page.valid
        })
        page.lastChanged.connect(function() {
            if (page != pages.currentItem)
                return
            pages.lastpage = page.last
        })
        page.next.connect(function() {
            var newview = wiz.submit(page.wizard_data)
            if (newview.view) {
                console.log('next view: ' + newview.view)
                var newpage = _loadNextComponent(newview.view, newview.wizard_data)
            } else {
                console.log('END')
            }
        })
        page.finish.connect(function() {
            // run wizard.submit() a final time, so that the navmap[view]['accept'] handler can run (if any)
            var newview = wiz.submit(page.wizard_data)
            _setWizardData(newview.wizard_data)
            console.log('wizard finished')
            // finish wizard
            wizard.doAccept()
        })
        page.prev.connect(function() {
            var wdata = wiz.prev()
        })

        pages.pagevalid = page.valid
        pages.lastpage = page.last

        return page
    }

    header: Item {
        visible: wizard.topBarVisible
        implicitHeight: visible ? headerLayout.implicitHeight : 0

        ColumnLayout {
            id: headerLayout
            width: parent.width
            spacing: 0

            // Add top padding for status bar on Android when using edge-to-edge
            Item {
                visible: app.statusBarHeight > 0
                Layout.fillWidth: true
                Layout.preferredHeight: app.statusBarHeight
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.preferredHeight: m3.topAppBarHeight
                Layout.leftMargin: 4
                Layout.rightMargin: m3.space16
                spacing: 0

                M3IconButton {
                    id: navButton
                    readonly property bool back: pages.currentIndex > 0
                    // the focus stays in the page, where the Android back key is caught (contentItem)
                    focusPolicy: Qt.NoFocus
                    visible: back || wizard.canCancel
                    tooltip: back ? qsTranslate('Wizard', 'Back') : qsTranslate('Wizard', 'Cancel')
                    icon.source: Qt.resolvedUrl(back ? '../../../icons/m3/arrow_back.png' : '../../../icons/m3/close.png')
                    icon.color: m3.surfaceOn
                    onClicked: {
                        if (back)
                            pages.prev()
                        else
                            wizard.doReject()
                    }
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: navButton.visible ? 4 : 12
                    spacing: 0

                    M3Text {
                        Layout.fillWidth: true
                        role: 'titleLarge'
                        elide: Text.ElideRight
                        text: wizard._pageTitle
                    }
                    M3Text {
                        Layout.fillWidth: true
                        visible: text !== ''
                        role: 'bodySmall'
                        color: m3.surfaceVariantOn
                        elide: Text.ElideRight
                        text: wizard._pageSubtitle
                    }
                }
            }
        }
    }

    // make layout contentItem so ElDialog TapHandler can focus on it and the Keys hook stays active
    contentItem: ColumnLayout {
        spacing: 0

        // root Item in Wizard, capture back button here and delegate to main
        Keys.onReleased: (event) => {
            if (event.key == Qt.Key_Back) {
                console.log("Back button within wizard")
                app.close() // this handles unwind of dialogs/stack
            }
        }

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
                currentItem.finish()
            }

            property bool pagevalid: false
            property bool lastpage: false

            // M3: no tap on the main button while the pages slide (a double tap would skip the next page)
            onCurrentIndexChanged: settleTimer.restart()

            Component.onCompleted: {
                _setWizardData({})
            }

            Binding {
                target: AppController
                property: 'secureWindow'
                // M3: and only while there is a page (none when the first page could not be opened)
                when: pages.visible && !!pages.contentChildren[pages.currentIndex]  // enables stacking multiple secureWindow dialogs
                value: pages.contentChildren[pages.currentIndex] ? pages.contentChildren[pages.currentIndex].securePage : false
            }
        }
    }

    Timer {
        id: settleTimer
        interval: 300
    }

    // bottom bar: the main button at the right of the content column, above the navigation bar strip
    footer: Rectangle {
        color: m3.surface
        implicitHeight: 72 + navStrip.height

        RowLayout {
            anchors.top: parent.top
            anchors.horizontalCenter: parent.horizontalCenter
            width: Math.min(parent.width, m3.maxContentWidth + 2 * m3.screenMargin(parent.width))
                - 2 * m3.screenMargin(parent.width)
            height: 72
            spacing: m3.space8

            M3Button {
                variant: 'text'
                focusPolicy: Qt.NoFocus
                visible: !wizard.topBarVisible && pages.currentIndex == 0
                text: qsTranslate('Wizard', 'Cancel')
                onClicked: wizard.doReject()
            }

            Item {
                Layout.fillWidth: true
                Layout.preferredHeight: 1
            }

            M3Button {
                text: qsTranslate('Wizard', 'Next')
                focusPolicy: Qt.NoFocus
                visible: !pages.lastpage
                enabled: pages.pagevalid
                onClicked: {
                    if (!settleTimer.running)
                        pages.next()
                }
            }
            M3Button {
                id: finishButton
                text: qsTranslate('Wizard', 'Finish')
                focusPolicy: Qt.NoFocus
                visible: pages.lastpage
                enabled: pages.pagevalid
                onClicked: {
                    if (!settleTimer.running)
                        pages.finish()
                }
            }
        }

        Item {
            id: navStrip
            anchors.bottom: parent.bottom
            width: parent.width
            height: app.keyboardFreeZone.state != 'visible' ? app.navigationBarHeight : 0
        }
    }
}
