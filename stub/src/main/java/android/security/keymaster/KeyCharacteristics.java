package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class KeyCharacteristics implements Parcelable {
    public KeymasterArguments hwEnforced;
    public KeymasterArguments swEnforced;

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    public static final Creator<KeyCharacteristics> CREATOR = new Creator<KeyCharacteristics>() {
        @Override
        public KeyCharacteristics createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public KeyCharacteristics[] newArray(int size) {
            throw new UnsupportedOperationException("STUB!");
        }
    };
}
