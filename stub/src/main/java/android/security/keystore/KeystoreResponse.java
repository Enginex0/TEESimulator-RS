package android.security.keystore;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class KeystoreResponse implements Parcelable {
    public final int error_code_;
    public final String error_msg_;

    protected KeystoreResponse(int error_code, String error_msg) {
        this.error_code_ = error_code;
        this.error_msg_ = error_msg;
    }

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    public static final Creator<KeystoreResponse> CREATOR = new Creator<KeystoreResponse>() {
        @Override
        public KeystoreResponse createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public KeystoreResponse[] newArray(int size) {
            throw new UnsupportedOperationException("STUB!");
        }
    };
}
