// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D
ParticleSystem3D {
    id: snow
    x: 50
    y: 300
    ParticleEmitter3D {
        id: snowEmitter
        emitRate: 500
        lifeSpan: 4000
        particle: snowParticle
        particleScale: 2
        particleScaleVariation: 1
        velocity: snowDirection
        shape: snowShape

        VectorDirection3D {
            id: snowDirection
            direction.y: -100
            direction.z: 0
        }

        SpriteParticle3D {
            id: snowParticle
            color: "#dcdcdc"
            maxAmount: 5000
            particleScale: 1
            sprite: snowTexture
            billboard: true

            Texture {
                id: snowTexture
                source: "snowflake.png"
            }
        }
    }
    ParticleShape3D {
        id: snowShape
        fill: true
        extents.x: 400
        extents.y: 1
        extents.z: 400
        type: ParticleShape3D.Cube
    }

    Wander3D {
        id: wander
        globalPace.x: 0.01
        globalAmount.x: -500
        uniqueAmount.x: 50
        uniqueAmount.y: 20
        uniqueAmount.z: 50
        uniqueAmountVariation: 0.1
        uniquePaceVariation: 0.2
        uniquePace.x: 0.03
        uniquePace.z: 0.03
        uniquePace.y: 0.01
        particles: snowParticle
    }
}
