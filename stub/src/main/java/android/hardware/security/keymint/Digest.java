package android.hardware.security.keymint;

public @interface Digest {
    int NONE = 0;
    int MD5 = 1;
    int SHA1 = 2;
    int SHA_2_224 = 3;
    int SHA_2_256 = 4;
    int SHA_2_384 = 5;
    int SHA_2_512 = 6;
}
