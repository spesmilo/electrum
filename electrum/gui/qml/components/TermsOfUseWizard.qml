import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "wizard"

Wizard {
    id: termsofusewizard

    wizardTitle: ""
    iconSource: ""
    header: null

    enter: null // disable transition

    wiz: Daemon.termsOfUseWizard
    finishButtonText: qsTr('Next')

    Component.onCompleted: {
        var view = wiz.startWizard()
        _loadNextComponent(view)
    }
}

