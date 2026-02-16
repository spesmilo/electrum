// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    SpriteParticle3D {
        id: spriteParticle
        color: "#ffffff"
        particleScale: 5.0
        maxAmount: 100
    }
    ParticleEmitter3D {
        id: particleEmitter
        particle: spriteParticle
        particleScale: 1.0
        particleEndScale: 1.5
        particleRotationVariation.x: 180
        particleRotationVariation.y: 180
        particleRotationVariation.z: 180
        particleRotationVelocityVariation.x: 200
        particleRotationVelocityVariation.y: 200
        particleRotationVelocityVariation.z: 200
        VectorDirection3D {
            id: dir3d
            direction.z: -100
            directionVariation.x: 10
            directionVariation.y: 10
        }
        velocity: dir3d
        emitRate: 10
        lifeSpan: 1000
        lifeSpanVariation: 100
    }
}
