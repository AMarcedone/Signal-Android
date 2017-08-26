/**
 * Copyright (C) 2011 Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.thoughtcrime.securesms.database;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import com.google.keytransparency.client.KeyTransparencyClient;
import com.google.keytransparency.client.KeyTransparencyException;
import com.google.keytransparency.client.LogReceiver;

import org.greenrobot.eventbus.EventBus;
import org.thoughtcrime.securesms.service.RegistrationService;
import org.thoughtcrime.securesms.util.Base64;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.guava.Optional;

import java.io.IOException;
import java.util.Arrays;

public class IdentityDatabase extends Database {

  private static final String TAG = IdentityDatabase.class.getSimpleName();

  private static final String TABLE_NAME           = "identities";
  private static final String ID                   = "_id";
  private static final String ADDRESS              = "address";
  private static final String IDENTITY_KEY         = "key";
  private static final String TIMESTAMP            = "timestamp";
  private static final String FIRST_USE            = "first_use";
  private static final String NONBLOCKING_APPROVAL = "nonblocking_approval";
  private static final String VERIFIED             = "verified";

  public static final String CREATE_TABLE = "CREATE TABLE " + TABLE_NAME +
      " (" + ID + " INTEGER PRIMARY KEY, " +
      ADDRESS + " TEXT UNIQUE, " +
      IDENTITY_KEY + " TEXT, " +
      FIRST_USE + " INTEGER DEFAULT 0, " +
      TIMESTAMP + " INTEGER DEFAULT 0, " +
      VERIFIED + " INTEGER DEFAULT 0, " +
      NONBLOCKING_APPROVAL + " INTEGER DEFAULT 0);";

  public enum VerifiedStatus {
    DEFAULT, VERIFIED, UNVERIFIED;

    public int toInt() {
      if      (this == DEFAULT)    return 0;
      else if (this == VERIFIED)   return 1;
      else if (this == UNVERIFIED) return 2;
      else throw new AssertionError();
    }

    public static VerifiedStatus forState(int state) {
      if      (state == 0) return DEFAULT;
      else if (state == 1) return VERIFIED;
      else if (state == 2) return UNVERIFIED;
      else throw new AssertionError("No such state: " + state);
    }
  }

  IdentityDatabase(Context context, SQLiteOpenHelper databaseHelper) {
    super(context, databaseHelper);
  }

  public Cursor getIdentities() {
    SQLiteDatabase database = databaseHelper.getReadableDatabase();
    return database.query(TABLE_NAME, null, null, null, null, null, null);
  }

  public @Nullable IdentityReader readerFor(@Nullable Cursor cursor) {
    if (cursor == null) return null;
    return new IdentityReader(cursor);
  }

  public Optional<IdentityRecord> getIdentity(Address address) {
    SQLiteDatabase database = databaseHelper.getReadableDatabase();
    Cursor         cursor   = null;

    try {
      cursor = database.query(TABLE_NAME, null, ADDRESS + " = ?",
                              new String[] {address.serialize()}, null, null, null);

      if (cursor != null && cursor.moveToFirst()) {
        return Optional.of(getIdentityRecord(cursor));
      }
    } catch (InvalidKeyException | IOException e) {
      throw new AssertionError(e);
    } finally {
      if (cursor != null) cursor.close();
    }

    return Optional.absent();
  }

  public void saveIdentity(Address address, IdentityKey identityKey, VerifiedStatus verifiedStatus,
                           boolean firstUse, long timestamp, boolean nonBlockingApproval)
  {
    SQLiteDatabase database          = databaseHelper.getWritableDatabase();
    String         identityKeyString = Base64.encodeBytes(identityKey.serialize());

    ContentValues contentValues = new ContentValues();
    contentValues.put(ADDRESS, address.serialize());
    contentValues.put(IDENTITY_KEY, identityKeyString);
    contentValues.put(TIMESTAMP, timestamp);
    contentValues.put(VERIFIED, verifiedStatus.toInt());
    contentValues.put(NONBLOCKING_APPROVAL, nonBlockingApproval ? 1 : 0);
    contentValues.put(FIRST_USE, firstUse ? 1 : 0);

    database.replace(TABLE_NAME, null, contentValues);

    EventBus.getDefault().post(new IdentityRecord(address, identityKey, verifiedStatus,
                                                  firstUse, timestamp, nonBlockingApproval));
  }

  public void setApproval(Address address, boolean nonBlockingApproval) {
    SQLiteDatabase database = databaseHelper.getWritableDatabase();

    ContentValues contentValues = new ContentValues(2);
    contentValues.put(NONBLOCKING_APPROVAL, nonBlockingApproval);

    database.update(TABLE_NAME, contentValues, ADDRESS + " = ?", new String[] {address.serialize()});
  }

  public void setVerified(Address address, IdentityKey identityKey, VerifiedStatus verifiedStatus) {
    SQLiteDatabase database = databaseHelper.getWritableDatabase();

    ContentValues contentValues = new ContentValues(1);
    contentValues.put(VERIFIED, verifiedStatus.toInt());

    int updated = database.update(TABLE_NAME, contentValues, ADDRESS + " = ? AND " + IDENTITY_KEY + " = ?",
                                  new String[] {address.serialize(), Base64.encodeBytes(identityKey.serialize())});

    if (updated > 0) {
      Optional<IdentityRecord> record = getIdentity(address);
      if (record.isPresent()) EventBus.getDefault().post(record.get());
    }
  }

  private IdentityRecord getIdentityRecord(@NonNull Cursor cursor) throws IOException, InvalidKeyException {
    String      address             = cursor.getString(cursor.getColumnIndexOrThrow(ADDRESS));
    String      serializedIdentity  = cursor.getString(cursor.getColumnIndexOrThrow(IDENTITY_KEY));
    long        timestamp           = cursor.getLong(cursor.getColumnIndexOrThrow(TIMESTAMP));
    int         verifiedStatus      = cursor.getInt(cursor.getColumnIndexOrThrow(VERIFIED));
    boolean     nonblockingApproval = cursor.getInt(cursor.getColumnIndexOrThrow(NONBLOCKING_APPROVAL)) == 1;
    boolean     firstUse            = cursor.getInt(cursor.getColumnIndexOrThrow(FIRST_USE))            == 1;
    IdentityKey identity            = new IdentityKey(Base64.decode(serializedIdentity), 0);

    return new IdentityRecord(Address.fromSerialized(address), identity, VerifiedStatus.forState(verifiedStatus), firstUse, timestamp, nonblockingApproval);
  }

  public static class IdentityRecord {

    private final Address        address;
    private final IdentityKey    identitykey;
    private final VerifiedStatus verifiedStatus;
    private final boolean        firstUse;
    private final long           timestamp;
    private final boolean        nonblockingApproval;

    private IdentityRecord(Address address,
                           IdentityKey identitykey, VerifiedStatus verifiedStatus,
                           boolean firstUse, long timestamp, boolean nonblockingApproval)
    {
      this.address             = address;
      this.identitykey         = identitykey;
      this.verifiedStatus      = verifiedStatus;
      this.firstUse            = firstUse;
      this.timestamp           = timestamp;
      this.nonblockingApproval = nonblockingApproval;
    }

    public Address getAddress() {
      return address;
    }

    public IdentityKey getIdentityKey() {
      return identitykey;
    }

    public long getTimestamp() {
      return timestamp;
    }

    public VerifiedStatus getVerifiedStatus() {
      return verifiedStatus;
    }

    public VerifiedStatus getKTVerifiedStatus () {
      final String KT_URL = "35.184.134.53:8080";
      final String SIGNAL_APP_ID = "SIGNAL";

      try {
        Log.w("KEYTRANSPARENCY", "Before KT Verification");
        KeyTransparencyClient.addVerboseLogsDestination(new LogReceiver() {
          @Override
          public long write(byte[] bytes) throws Exception {
            Log.w("KeyTransparency", new String(bytes, "UTF-8"));
            return bytes.length;
          }
        });

        KeyTransparencyClient.addKtServerIfNotExists(KT_URL, true, null, null);
      } catch (KeyTransparencyException e) {
        Log.w("KEYTRANSPARENCY", "AddServer Exception", e);
        return VerifiedStatus.UNVERIFIED;
      }

      try{
        byte[] receivedKey = KeyTransparencyClient.getEntry(KT_URL,getAddress().toPhoneString(),SIGNAL_APP_ID);
        Log.w("KEYTRANSPARENCY", "Received key: " + bytesToHex(receivedKey) + ", actual Key: " + bytesToHex(getIdentityKey().getPublicKey().serialize()));
        if (receivedKey == null){
          return VerifiedStatus.DEFAULT;
        }else if(Arrays.equals(receivedKey, getIdentityKey().getPublicKey().serialize())){
          return VerifiedStatus.VERIFIED;
        } else {
          return VerifiedStatus.UNVERIFIED;
        }
      } catch (KeyTransparencyException e) {
        e.printStackTrace();
        Log.w("KEYTRANSPARENCY", "GetEntry Exception", e);
        // If there is a network error or an invalid proof, we conservatively show the Kt Status as failing.
        return VerifiedStatus.UNVERIFIED;
      }

    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
      char[] hexChars = new char[bytes.length * 2];
      for ( int j = 0; j < bytes.length; j++ ) {
        int v = bytes[j] & 0xFF;
        hexChars[j * 2] = hexArray[v >>> 4];
        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
      }
      return new String(hexChars);
    }


    public boolean isApprovedNonBlocking() {
      return nonblockingApproval;
    }

    public boolean isFirstUse() {
      return firstUse;
    }

    @Override
    public String toString() {
      return "{address: " + address + ", identityKey: " + identitykey + ", verifiedStatus: " + verifiedStatus + ", firstUse: " + firstUse + "}";
    }

  }

  public class IdentityReader {
    private final Cursor cursor;

    public IdentityReader(@NonNull Cursor cursor) {
      this.cursor = cursor;
    }

    public @Nullable IdentityRecord getNext() {
      if (cursor.moveToNext()) {
        try {
          return getIdentityRecord(cursor);
        } catch (IOException | InvalidKeyException e) {
          throw new AssertionError(e);
        }
      }

      return null;
    }

    public void close() {
      cursor.close();
    }
  }

}
