package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class KeyDescriptor implements Parcelable {
    public String alias;
    public byte[] blob;
    public int domain = 0;
    public long nspace = 0;

    public static final Creator<KeyDescriptor> CREATOR = new Creator<KeyDescriptor>() {
        @Override
        public KeyDescriptor createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public KeyDescriptor[] newArray(int size) {
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
