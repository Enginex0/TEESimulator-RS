package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class KeyMetadata implements Parcelable {
    public Authorization[] authorizations;
    public byte[] certificate;
    public byte[] certificateChain;
    public KeyDescriptor key;
    public int keySecurityLevel = 0;
    public long modificationTimeMs = 0;

    public static final Creator<KeyMetadata> CREATOR = new Creator<KeyMetadata>() {
        @Override
        public KeyMetadata createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public KeyMetadata[] newArray(int size) {
            throw new UnsupportedOperationException("STUB!");
        }
    };

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public void writeToParcel(@NonNull Parcel parcel, int i) {
        throw new UnsupportedOperationException("STUB!");
    }
}
