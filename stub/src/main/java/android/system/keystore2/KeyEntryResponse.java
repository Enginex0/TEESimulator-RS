package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class KeyEntryResponse implements Parcelable {
    public IKeystoreSecurityLevel iSecurityLevel;
    public KeyMetadata metadata;

    public static final Creator<KeyEntryResponse> CREATOR = new Creator<KeyEntryResponse>() {
        @Override
        public KeyEntryResponse createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public KeyEntryResponse[] newArray(int size) {
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
