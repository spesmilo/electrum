// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: modelShapeSystem
    ParticleEmitter3D {
        id: modelShapeEmitter
        shape: targetShape
        velocity: modelShapeDirection
        emitRate: 100
        lifeSpanVariation: 100
        lifeSpan: 4000
        particle: modelShapeParticle
        particleRotationVelocityVariation.x: 200
        particleRotationVariation.z: 180
        particleRotationVelocityVariation.y: 200

        SpriteParticle3D {
            id: modelShapeParticle
            color: "#ffffff"
            fadeInDuration: 1500
            fadeOutDuration: 1500
            particleScale: 2
            maxAmount: 2000

            VectorDirection3D {
                id: modelShapeDirection
                directionVariation.z: 2
                direction.y: 2
                directionVariation.x: 2
                direction.z: 0
                directionVariation.y: 2
            }
        }
        particleRotationVelocityVariation.z: 200
        particleEndScale: 1.5
        particleRotationVariation.y: 180
        particleRotationVariation.x: 180
    }
    ParticleModelShape3D {
        id: targetShape
        fill: false
        delegate: Model {
            source: "#Cube"
        }
    }
}
