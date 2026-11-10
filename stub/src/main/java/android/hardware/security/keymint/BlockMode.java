package android.hardware.security.keymint;

public @interface BlockMode {
    public static final int ECB = 1;
    public static final int CBC = 2;
    public static final int CTR = 3;
    public static final int GCM = 32;
}
