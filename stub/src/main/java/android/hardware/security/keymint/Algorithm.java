package android.hardware.security.keymint;

public @interface Algorithm {
    int AES = 32;
    int EC = 3;
    int HMAC = 128;
    int RSA = 1;
    int TRIPLE_DES = 33;
    // KeyMint v5 (Android 17).
    int ML_DSA = 4;
}
