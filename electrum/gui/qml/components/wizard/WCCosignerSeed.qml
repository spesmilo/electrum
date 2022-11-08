import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "../controls"

WCHaveSeed {
    id: root

    headingtext: qsTr('Cosigner #%1 of %2').arg(cosigner).arg(participants)

    property int cosigner: 0
    property int participants: 0

    function apply() {
        console.log('apply fn called')
        wizard_data['cosigner_seed'] = seed
        wizard_data['cosigner_seed_variant'] = seed_variant
        wizard_data['cosigner_seed_type'] = seed_type
        wizard_data['cosigner_seed_extend'] = seed_extend
        wizard_data['cosigner_seed_extra_words'] = seed_extra_words
    }

    onReadyChanged: {
        if (!ready)
            return

        participants = wizard_data['multisig_participants']
        cosigner = wizard_data['multisig_current_cosigner']
    }
}
