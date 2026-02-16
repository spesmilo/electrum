// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
import QtQuick
import QtQuick.Controls.Material

QtObject {
    property SystemPalette palette: SystemPalette { }
    function withAlpha(color, alpha) {
        return Qt.hsla(color.hslHue, color.hslSaturation, color.hslLightness, alpha)
    }
    property color selectionColor: withAlpha(palette.highlight, 0.5)
    property color pageSearchResultsColor: withAlpha(Qt.lighter(Material.accentColor, 1.5), 0.5)
    property color currentSearchResultStrokeColor: Material.accentColor
    property real currentSearchResultStrokeWidth: 2
}
