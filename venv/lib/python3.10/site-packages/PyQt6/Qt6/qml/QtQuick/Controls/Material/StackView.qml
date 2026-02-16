// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Material

T.StackView {
    id: control

    component LineAnimation: NumberAnimation {
        duration: 200
        easing.type: Easing.OutCubic
    }

    component FadeIn: LineAnimation {
        property: "opacity"
        from: 0.0
        to: 1.0
    }

    component FadeOut: LineAnimation {
        property: "opacity"
        from: 1.0
        to: 0.0
    }

    popEnter: Transition {
        // slide_in_left
        LineAnimation { property: "x"; from: (control.mirrored ? -0.5 : 0.5) *  -control.width; to: 0 }
        FadeIn {}
    }

    popExit: Transition {
        // slide_out_right
        LineAnimation { property: "x"; from: 0; to: (control.mirrored ? -0.5 : 0.5) * control.width }
        FadeOut {}
    }

    pushEnter: Transition {
        // slide_in_right
        LineAnimation { property: "x"; from: (control.mirrored ? -0.5 : 0.5) * control.width; to: 0 }
        FadeIn {}
    }

    pushExit: Transition {
        // slide_out_left
        LineAnimation { property: "x"; from: 0; to: (control.mirrored ? -0.5 : 0.5) * -control.width }
        FadeOut {}
    }

    replaceEnter: Transition {
        // slide_in_right
        LineAnimation { property: "x"; from: (control.mirrored ? -0.5 : 0.5) * control.width; to: 0 }
        FadeIn {}
    }

    replaceExit: Transition {
        // slide_out_left
        LineAnimation { property: "x"; from: 0; to: (control.mirrored ? -0.5 : 0.5) * -control.width }
        FadeOut {}
    }
}
