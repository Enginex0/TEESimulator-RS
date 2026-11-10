package android.security.keystore;

import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import android.security.keymaster.KeyCharacteristics;

public interface IKeystoreKeyCharacteristicsCallback extends IInterface {
    void onFinished(KeystoreResponse keystoreResponse, KeyCharacteristics keyCharacteristics) throws RemoteException;

    public static abstract class Stub {
        public static IKeystoreKeyCharacteristicsCallback asInterface(IBinder b) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
