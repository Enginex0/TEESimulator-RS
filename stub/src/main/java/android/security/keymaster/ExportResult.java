package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class ExportResult implements Parcelable {
    public final byte[] exportData;
    public final int resultCode;

    public ExportResult(int resultCode) {
        this.resultCode = resultCode;
        this.exportData = new byte[0];
    }

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    public static final Creator<ExportResult> CREATOR = new Creator<ExportResult>() {
        @Override
        public ExportResult createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public ExportResult[] newArray(int size) {
            throw new UnsupportedOperationException("STUB!");
        }
    };
}
