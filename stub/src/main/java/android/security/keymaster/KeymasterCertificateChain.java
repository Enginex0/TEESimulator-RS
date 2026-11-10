package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

import java.util.List;

public class KeymasterCertificateChain implements Parcelable {
    private List<byte[]> mCertificates;

    public KeymasterCertificateChain() {
        this.mCertificates = null;
    }

    public KeymasterCertificateChain(List<byte[]> mCertificates) {
        this.mCertificates = mCertificates;
    }

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    public static final Creator<KeymasterCertificateChain> CREATOR = new Creator<KeymasterCertificateChain>() {
        @Override
        public KeymasterCertificateChain createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public KeymasterCertificateChain[] newArray(int size) {
            throw new UnsupportedOperationException("STUB!");
        }
    };
}
