package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;

public class KeymasterArguments implements Parcelable {

    private static final long UINT32_RANGE = 1L << 32;
    public static final long UINT32_MAX_VALUE = UINT32_RANGE - 1;

    private static final BigInteger UINT64_RANGE = BigInteger.ONE.shiftLeft(64);
    public static final BigInteger UINT64_MAX_VALUE = UINT64_RANGE.subtract(BigInteger.ONE);

    private List<KeymasterArgument> mArguments;

    public static final @NonNull Parcelable.Creator<KeymasterArguments> CREATOR = new Parcelable.Creator<KeymasterArguments>() {
        @Override
        public KeymasterArguments createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public KeymasterArguments[] newArray(int size) {
            throw new UnsupportedOperationException("STUB!");
        }
    };

    public KeymasterArguments() {
        throw new UnsupportedOperationException("STUB!");
    }

    private KeymasterArguments(Parcel in) {
        throw new UnsupportedOperationException("STUB!");
    }

    public void addEnum(int tag, int value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public void addEnums(int tag, int... values) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getEnum(int tag, int defaultValue) {
        throw new UnsupportedOperationException("STUB!");
    }

    public List<Integer> getEnums(int tag) {
        throw new UnsupportedOperationException("STUB!");
    }

    private void addEnumTag(int tag, int value) {
        throw new UnsupportedOperationException("STUB!");
    }

    private int getEnumTagValue(KeymasterArgument arg) {
        throw new UnsupportedOperationException("STUB!");
    }

    public void addUnsignedInt(int tag, long value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public long getUnsignedInt(int tag, long defaultValue) {
        throw new UnsupportedOperationException("STUB!");
    }

    public void addUnsignedLong(int tag, BigInteger value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public List<BigInteger> getUnsignedLongs(int tag) {
        throw new UnsupportedOperationException("STUB!");
    }

    private void addLongTag(int tag, BigInteger value) {
        throw new UnsupportedOperationException("STUB!");
    }

    private BigInteger getLongTagValue(KeymasterArgument arg) {
        throw new UnsupportedOperationException("STUB!");
    }

    public void addBoolean(int tag) {
        throw new UnsupportedOperationException("STUB!");
    }

    public boolean getBoolean(int tag) {
        throw new UnsupportedOperationException("STUB!");
    }

    public void addBytes(int tag, byte[] value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public byte[] getBytes(int tag, byte[] defaultValue) {
        throw new UnsupportedOperationException("STUB!");
    }

    public void addDate(int tag, Date value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public void addDateIfNotNull(int tag, Date value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public Date getDate(int tag, Date defaultValue) {
        throw new UnsupportedOperationException("STUB!");
    }

    private KeymasterArgument getArgumentByTag(int tag) {
        throw new UnsupportedOperationException("STUB!");
    }

    public boolean containsTag(int tag) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int size() {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public void writeToParcel(Parcel out, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }

    public void readFromParcel(Parcel in) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    public static BigInteger toUint64(long value) {
        throw new UnsupportedOperationException("STUB!");
    }
}
