package android.hardware.security.keymint;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public final class KeyParameterValue implements Parcelable {
    public static final int algorithm = 1;
    public static final int blob = 14;
    public static final int blockMode = 2;
    public static final int boolValue = 10;
    public static final int dateTime = 13;
    public static final int digest = 4;
    public static final int ecCurve = 5;
    public static final int hardwareAuthenticatorType = 8;
    public static final int integer = 11;
    public static final int invalid = 0;
    public static final int keyPurpose = 7;
    public static final int longInteger = 12;
    public static final int origin = 6;
    public static final int paddingMode = 3;
    public static final int securityLevel = 9;
    public static final Creator<KeyParameterValue> CREATOR = new Creator<KeyParameterValue>() {
        @Override
        public KeyParameterValue createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public KeyParameterValue[] newArray(int size) {
            throw new UnsupportedOperationException("STUB!");
        }
    };

    public KeyParameterValue() {
        throw new UnsupportedOperationException("STUB!");
    }

    protected KeyParameterValue(Parcel in) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue invalid(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue algorithm(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue blockMode(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue paddingMode(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue digest(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue ecCurve(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue origin(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue keyPurpose(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue hardwareAuthenticatorType(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue securityLevel(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue boolValue(boolean _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue integer(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue longInteger(long _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue dateTime(long _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue blob(byte[] _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getTag() {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getInvalid() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setInvalid(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getAlgorithm() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setAlgorithm(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getBlockMode() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setBlockMode(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getPaddingMode() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setPaddingMode(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getDigest() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setDigest(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getEcCurve() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setEcCurve(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getOrigin() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setOrigin(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getKeyPurpose() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setKeyPurpose(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getHardwareAuthenticatorType() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setHardwareAuthenticatorType(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getSecurityLevel() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setSecurityLevel(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public boolean getBoolValue() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setBoolValue(boolean _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getInteger() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setInteger(int _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public long getLongInteger() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setLongInteger(long _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public long getDateTime() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setDateTime(long _value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public byte[] getBlob() {
        throw new UnsupportedOperationException("STUB!");
    }

    public void setBlob(byte[] _value) {
        throw new UnsupportedOperationException("STUB!");
    }


    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public void writeToParcel(@NonNull Parcel parcel, int i) {
        throw new UnsupportedOperationException("STUB!");
    }
}
