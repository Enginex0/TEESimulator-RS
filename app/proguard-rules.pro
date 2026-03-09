-keep class org.matrix.TEESimulator.interception.keystore.** { *; }

-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
-dontwarn javax.naming.**

-keepclasseswithmembers class org.matrix.TEESimulator.App {
    public static void main(java.lang.String[]);
}

-keepclasseswithmembers class org.matrix.TEESimulator.pki.NativeCertGen {
    native <methods>;
    *;
}
-keep class org.matrix.TEESimulator.pki.CertGenConfig { *; }
