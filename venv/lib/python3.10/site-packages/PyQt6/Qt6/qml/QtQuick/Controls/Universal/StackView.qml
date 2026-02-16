// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Universal

T.StackView {
    id: control

    popEnter: Transition {
        ParallelAnimation {
            NumberAnimation { property: "opacity"; from: 0; to: 1; duration: 200; easing.type: Easing.InQuint }
            NumberAnimation { property: "x"; from: (control.mirrored ? -0.3 : 0.3) * -control.width; to: 0; duration: 400; easing.type: Easing.OutCubic }
        }
    }

    popExit: Transition {
        NumberAnimation { property: "opacity"; from: 1; to: 0; duration: 200; easing.type: Easing.OutQuint }
    }

    pushEnter: Transition {
        ParallelAnimation {
            NumberAnimation { property: "opacity"; from: 0; to: 1; duration: 200; easing.type: Easing.InQuint }
            NumberAnimation { property: "x"; from: (control.mirrored ? -0.3 : 0.3) * control.width; to: 0; duration: 400; easing.type: Easing.OutCubic }
        }
    }

    pushExit: Transition {
        NumberAnimation { property: "opacity"; from: 1; to: 0; duration: 200; easing.type: Easing.OutQuint }
    }

    replaceEnter: Transition {
        ParallelAnimation {
            NumberAnimation { property: "opacity"; from: 0; to: 1; duration: 200; easing.type: Easing.InQuint }
            NumberAnimation { property: "x"; from: (control.mirrored ? -0.3 : 0.3) * control.width; to: 0; duration: 400; easing.type: Easing.OutCubic }
        }
    }

    replaceExit: Transition {
        NumberAnimation { property: "opacity"; from: 1; to: 0; duration: 200; easing.type: Easing.OutQuint }
    }
}
