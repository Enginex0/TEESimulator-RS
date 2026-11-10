package android.security.keystore;

import android.os.IBinder;
import android.os.RemoteException;
import android.security.keymaster.KeymasterCertificateChain;

public interface IKeystoreCertificateChainCallback {
    void onFinished(KeystoreResponse keystoreResponse, KeymasterCertificateChain keymasterCertificateChain)
            throws RemoteException;

    public static abstract class Stub {
        public static IKeystoreCertificateChainCallback asInterface(IBinder b) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
