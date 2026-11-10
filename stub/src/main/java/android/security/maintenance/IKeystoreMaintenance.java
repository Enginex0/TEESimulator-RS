package android.security.maintenance;

import android.os.IBinder;

/**
 * Compile-time stub for the hidden keystore2 maintenance binder
 * ({@code android.security.maintenance.IKeystoreMaintenance}).
 *
 * <p>This module is a {@code compileOnly} dependency, so the real framework class
 * (which carries the actual {@code TRANSACTION_*} codes) is loaded at runtime. We
 * only need the {@link #DESCRIPTOR} token to parse the transaction parcel and the
 * inner {@code Stub} class so {@code getTransactCode} can reflect the real codes.
 */
public interface IKeystoreMaintenance {
    String DESCRIPTOR = "android.security.maintenance.IKeystoreMaintenance";

    class Stub {
        public static IKeystoreMaintenance asInterface(IBinder b) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
