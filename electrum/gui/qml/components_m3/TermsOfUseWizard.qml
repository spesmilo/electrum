import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "wizard"

// Material 3 terms of use of the first start (app.termsOfUseWizard).
// repeats: components/TermsOfUseWizard.qml:7-22 (verbatim; `header: null` is `topBarVisible: false`
// of the Material 3 Wizard: no top bar, "Cancel" and "Next" at the bottom, as the classic buttons).
Wizard {
    id: termsofusewizard

    wizardTitle: ""
    iconSource: ""
    topBarVisible: false
    canCancel: false

    enter: null // disable transition

    wiz: Daemon.termsOfUseWizard
    finishButtonText: qsTranslate('TermsOfUseWizard', 'Next')

    Component.onCompleted: {
        var view = wiz.startWizard()
        _loadNextComponent(view)
    }
}
