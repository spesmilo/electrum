package org.electroncash.electroncash3

import android.graphics.Bitmap
import android.view.View
import android.widget.ImageView
import androidx.fragment.app.Fragment
import com.google.zxing.WriterException
import com.google.zxing.integration.android.IntentIntegrator
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.google.zxing.qrcode.encoder.Encoder
import java.util.*


fun scanQR(fragment: Fragment) {
    IntentIntegrator.forSupportFragment(fragment)
        .setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
        .setPrompt("")
        .setBeepEnabled(false)
        .initiateScan()
}


private val qrListeners = WeakHashMap<View, View.OnLayoutChangeListener>()

fun showQR(img: ImageView, text: String) {
    showQRNow(img, text)

    // View sizes aren't available in onStart, so install a layout listener.
    val listener = View.OnLayoutChangeListener { _, _, _, _, _, _, _, _, _ ->
        showQRNow(img, text)
    }
    img.addOnLayoutChangeListener(listener)
    val oldListener = qrListeners.put(img, listener)
    if (oldListener != null) {
        img.removeOnLayoutChangeListener(oldListener)
    }
}

private fun showQRNow(img: ImageView, text: String) {
    val resolution = img.height  // The layout XML should set this using  R.dimen.qr_...

    if (resolution > 0) {
        // The zxing renderer outputs an equal number of pixels per block, which can cause a
        // lot of extra padding for large QRs. So we instead render at one pixel per block and
        // scale up using nearest neighbor.
        try {
            val BLACK = 0xFF000000.toInt()
            val WHITE = 0xFFFFFFFF.toInt()
            val matrix = Encoder.encode(text, ErrorCorrectionLevel.L).matrix
            val pixels = IntArray(matrix.width * matrix.height) {
                if (matrix.get(it % matrix.width, it / matrix.width).toInt() == 1)
                    BLACK else WHITE
            }
            val smallBitmap = Bitmap.createBitmap(
                pixels, matrix.width, matrix.height, Bitmap.Config.ARGB_8888)
            img.setImageBitmap(
                Bitmap.createScaledBitmap(smallBitmap, resolution, resolution, false))
        } catch (e: WriterException) {
            if (e.message == "Data too big") {
                img.setImageDrawable(null)
            } else {
                throw e
            }
        }
    }
}