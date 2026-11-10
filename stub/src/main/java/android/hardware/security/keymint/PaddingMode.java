package android.hardware.security.keymint;

public @interface PaddingMode {
    public static final int NONE = 1;
    public static final int RSA_OAEP = 2;
    public static final int RSA_PSS = 3;
    public static final int RSA_PKCS1_1_5_ENCRYPT = 4;
    public static final int RSA_PKCS1_1_5_SIGN = 5;
    public static final int PKCS7 = 64;
}
