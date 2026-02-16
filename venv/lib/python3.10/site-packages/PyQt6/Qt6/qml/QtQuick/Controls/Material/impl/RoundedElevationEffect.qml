// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick.Controls.Material
import QtQuick.Controls.Material.impl

ElevationEffect {
    required property int roundedScale

    _shadows: roundedScale === Material.NotRounded ? _defaultShadows : roundedShadows()

    function roundedShadows() {
        // Make a deep copy.
        let shadows = [..._defaultShadows]
        for (let i = 0, strength = 0.95; i < shadows.length; ++i) {
            // See comment on BoxShadow's strength property for why we do this.
            shadows[i].strength = strength
            // We don't want the strength to be too high for the controls with very slightly rounded
            // corners, as they are quite close to the non-rounded ones in terms of not needing adjustments.
            // This is still not great for the higher elevations for ExtraSmallScale, but it's as good
            // as I can get it.
            strength = Math.max(0.05, strength - (roundedScale > Material.ExtraSmallScale ? 0.1 : 0.3))

            // The values at index 0 are already 0, and we don't want our Math.max(1, ...) code to affect them.
            if (i > 0) {
                // The blur values for e.g. buttons with rounded corners are too large, so we reduce them.
                for (let angularShadowIndex = 0; angularShadowIndex < shadows[i].angularValues.length; ++angularShadowIndex) {
                    shadows[i].angularValues[angularShadowIndex].blur =
                        Math.max(1, Math.floor(shadows[i].angularValues[angularShadowIndex].blur / 4))
                }
            }
        }
        return shadows
    }
}
