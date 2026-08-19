package org.electrum.qr;

public interface ScanCallback {
    boolean onPart(String text, byte[] binary);
}
