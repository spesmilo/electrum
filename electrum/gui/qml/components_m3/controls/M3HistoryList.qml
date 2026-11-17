import QtQuick
import QtQuick.Controls

import org.electrum 1.0

// History list of the Material 3 GUI (M2-MAP F-10): M3HistoryDelegate rows of a transaction list model under date
// sections, in a column of at most m3.maxContentWidth. Used by the History tab (the wallet history) and by the
// address history page (QEAddressDetails.historyModel).
// API (zone probe R-5): `model` (a QETransactionListModel), positionViewAtBeginning(). The owner initializes the
// model (initModel(), lazy), sizes the list and shows the empty state; the list only shows the rows.
// repeats: components/History.qml:51-75 (the section labels and the section delegate) @ e6df7e1c8; moved here
// verbatim from components_m3/HistoryTab.qml:29-78 @ 79f59c445 (strings keep the context of the classic History).
Item {
    id: root

    property QtObject model

    function positionViewAtBeginning() {
        listview.positionViewAtBeginning()
    }

    ListView {
        id: listview
        anchors.fill: parent
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        model: root.model
        topMargin: m3.space8
        bottomMargin: m3.space16

        readonly property int _columnWidth: Math.min(width, m3.maxContentWidth) - 2 * m3.screenMargin(width)

        readonly property var sectionLabels: ({
            'local': qsTranslate('History', 'Local'),
            'mempool': qsTranslate('History', 'Mempool'),
            'today': qsTranslate('History', 'Today'),
            'yesterday': qsTranslate('History', 'Yesterday'),
            'thisweek': qsTranslate('History', 'Earlier this week'),
            'lastweek': qsTranslate('History', 'Last week'),
            'thismonth': qsTranslate('History', 'Earlier this month'),
            'lastmonth': qsTranslate('History', 'Last month'),
            'older': qsTranslate('History', 'Older')
        })

        section.property: 'section'
        section.criteria: ViewSection.FullString
        section.delegate: Item {
            required property string section
            width: ListView.view.width
            height: sectionHeader.implicitHeight
            M3SectionHeader {
                id: sectionHeader
                width: listview._columnWidth
                anchors.horizontalCenter: parent.horizontalCenter
                leftPadding: m3.space16
                text: section in listview.sectionLabels ? listview.sectionLabels[section] : section
            }
        }

        delegate: Item {
            width: ListView.view.width
            height: row.height
            M3HistoryDelegate {
                id: row
                width: listview._columnWidth
                anchors.horizontalCenter: parent.horizontalCenter
            }
        }

        ScrollIndicator.vertical: ScrollIndicator { }
    }
}
