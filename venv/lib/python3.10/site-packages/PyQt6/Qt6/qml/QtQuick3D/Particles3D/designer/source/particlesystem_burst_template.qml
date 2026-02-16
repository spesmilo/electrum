// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: burstSystem
    ParticleEmitter3D {
        id: burstEmitter
        emitBursts: emitBurst
        velocity: burstDirection
        particle: burstParticle
        lifeSpan: 4000
        SpriteParticle3D {
            id: burstParticle
            maxAmount: 200
        }

        VectorDirection3D {
            id: burstDirection
            directionVariation.z: 10
            directionVariation.y: 10
            directionVariation.x: 10
        }

        EmitBurst3D {
            id: emitBurst
            time: 500
            duration: 100
            amount: 20
        }
    }
}
