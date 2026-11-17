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
// the first 300 ms after a page change is ignored (no double tap through a page); a page without a Material 3
// version (a new upstream page, a broken file, a plugin page not in _m3PluginPages) is the classic page, shown
// as a dark classic island, with a warning in the log.
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
    property bool _classicFallback: false

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
    // page, the one in the qml_m3 directory of the plugin); without one the classic page, with a warning
    function _pageUrl(name) {
        var m3name = name
        var plugin = name.match(/\/plugins\/([^\/]+)\/qml\/([^\/]+)\.qml$/)
        if (plugin) {
            var known = _m3PluginPages[plugin[1]]
            m3name = known && known.indexOf(plugin[2]) >= 0
                ? name.replace('/plugins/' + plugin[1] + '/qml/', '/plugins/' + plugin[1] + '/qml_m3/')
                : ''
        }
        if (m3name !== '') {
            var url = Qt.resolvedUrl(m3name)
            var comp = Qt.createComponent(url)
            if (comp.status != Component.Error) {
                _classicFallback = false
                return url
            }
            console.warn('M3 wizard: ' + comp.errorString())
        }
        console.warn('M3 wizard: no Material 3 page for ' + name + ', using the classic one')
        _classicFallback = true
        // a plugin page name is relative to the wizard directory: the same file as for the classic wizard
        return plugin ? Qt.resolvedUrl(name) : Qt.resolvedUrl('../../components/wizard/' + name)
    }

    // M3: a color the attached Material takes as an explicit value (Qt 6.10 ignores a color value, and a string
    // equal to the default of the theme, keeping the inherited color then): the string of the color, one step off
    function _explicitColor(c) {
        return Qt.rgba(c.r, c.g, c.b < 0.5 ? c.b + 1/255 : c.b - 1/255, 1).toString()
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

        var url = _pageUrl(wiz.viewToComponent(view))
        var comp = Qt.createComponent(url)
        if (comp.status == Component.Error) {
            console.log(comp.errorString())
            return null
        }

        // make a deepcopy of wdata and pass it to the component
        var wdata_copy={}
        Object.assign(wdata_copy, wdata)
        var page = comp.createObject(pages, {wizard_data: wdata_copy})
        if (_classicFallback) {
            // M3: a classic page is a dark classic island (its colors come from `constants` of the dark window);
            // the explicit colors of the popup would be inherited otherwise (dark text on dark panes)
            var classic = app.contentItem.Material  // the theme of the dark window
            page.Material.theme = Material.Dark
            page.Material.accent = _explicitColor(classic.accent)
            page.Material.primary = _explicitColor(classic.primary)
            page.Material.background = _explicitColor(classic.background)
            page.Material.foreground = _explicitColor(classic.foreground)
            console.log('M3 wizard: classic page shown as a dark island')
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
                when: pages.visible  // enables stacking multiple secureWindow dialogs
                value: pages.contentChildren[pages.currentIndex].securePage
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
