import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

ListView {
    id: root

    property int width_left_exclusion_zone: 0
    property int width_right_exclusion_zone: 0

    MouseArea {
        anchors {top: root.top; left: root.left; bottom: root.bottom }
        visible: width_left_exclusion_zone > 0
        width: width_left_exclusion_zone
    }

    MouseArea {
        anchors { top: root.top; right: root.right; bottom: root.bottom }
        visible: width_right_exclusion_zone > 0
        width: width_right_exclusion_zone
    }

    // determine distance from sides of window and reserve some
    // space using noop mouseareas in order to not emit clicks when
    // android back gesture is used
    function layoutExclusionZones() {
        var reserve = constants.fingerWidth / 2
        var p = root.mapToGlobal(0, 0)  // note: coords on whole *screen*, not just window
        width_left_exclusion_zone = Math.max(0, reserve - p.x)
        p = root.mapToGlobal(width, 0)
        width_right_exclusion_zone = Math.max(0, reserve - (app.width - p.x))
    }

    Component.onCompleted: {
        if (AppController.isAndroid()) {
            layoutExclusionZones()
        }
    }
}
