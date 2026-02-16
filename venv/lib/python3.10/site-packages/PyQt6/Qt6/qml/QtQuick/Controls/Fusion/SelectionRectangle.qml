// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Fusion
import QtQuick.Controls.Fusion.impl

T.SelectionRectangle {
    id: control

    topLeftHandle: Item {
        width: 20
        height: 20
        visible: SelectionRectangle.control.active
        // This item is deliberately empty. Selection handles don't feel at home
        // for this style. But we provide an invisible handle that the user can
        // drag on.
    }

    bottomRightHandle: Item {
        width: 20
        height: 20
        visible: SelectionRectangle.control.active
        // This item is deliberately empty. Selection handles don't feel at home
        // for this style. But we provide an invisible handle that the user can
        // drag on.
    }
}
