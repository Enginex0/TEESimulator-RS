package android.system.keystore2;

import android.os.IBinder;
import android.os.Binder;
import android.os.IInterface;

public interface IKeystoreOperation extends IInterface {
    public static final java.lang.String DESCRIPTOR = "android.system.keystore2.IKeystoreOperation";

    public void updateAad(byte[] aadInput);

    public byte[] update(byte[] input);

    public byte[] finish(byte[] input, byte[] signature);

    public void abort() throws android.os.RemoteException;

    abstract class Stub extends Binder implements IKeystoreOperation {
        public static IKeystoreOperation asInterface(IBinder b) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public IBinder asBinder() {
            return this;
        }

        @Override
        public void updateAad(byte[] aadInput) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
