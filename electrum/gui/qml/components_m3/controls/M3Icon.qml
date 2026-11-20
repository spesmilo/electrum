import QtQuick
import QtQuick.Controls.impl

// Monochrome icon tinted with `color` (the alpha channel of the image is the shape)
IconImage {
    property int size: 24

    sourceSize.width: size
    sourceSize.height: size
    width: size
    height: size
    color: m3.surfaceVariantOn
    fillMode: Image.PreserveAspectFit
}
