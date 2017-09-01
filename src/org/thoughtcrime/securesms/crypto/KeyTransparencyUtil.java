package org.thoughtcrime.securesms.crypto;

import android.util.Log;

import com.google.keytransparency.client.KeyTransparencyClient;
import com.google.keytransparency.client.KeyTransparencyException;

import org.whispersystems.libsignal.IdentityKeyPair;

public class KeyTransparencyUtil {

    private static final String DEFAULT_AUTHORIZED_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"+
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBUzgqmfMNYETU67U5kklSx/wfqcd\n"+
            "Zn+mxLDouFyti/hdshzOlZYfb51YG+zhgQQ7PpTzoj3Lz/EdfeZauwDKPA==\n"+
            "-----END PUBLIC KEY-----";
    private static final String DEFAULT_AUTHORIZED_PRIVATE_KEY = "-----BEGIN EC PRIVATE KEY-----\n" +
            "MHcCAQEEIKrzmO7QnfhTXOSP7hPk6j5fO2b36z97w35Fdr6d0qUkoAoGCCqGSM49\n" +
            "AwEHoUQDQgAEBUzgqmfMNYETU67U5kklSx/wfqcdZn+mxLDouFyti/hdshzOlZYf\n" +
            "b51YG+zhgQQ7PpTzoj3Lz/EdfeZauwDKPA==\n" +
            "-----END EC PRIVATE KEY-----";

    public static final String KT_LOG_TAG = "KEY_TRANSPARENCY";

    private static final int DEFAULT_RETRY_COUNT = 10;
    public static final String KT_URL = "35.184.134.53:8080";
    public static final String SIGNAL_APP_ID = "SIGNAL";


    public static void updateKeyTransparencyEntry(String number, IdentityKeyPair identityKey) throws KeyTransparencyException {

        KeyTransparencyClient.addKtServerIfNotExists(KT_URL, true, null, null);
        KeyTransparencyClient.setTimeout(10000);
        Log.w(KT_LOG_TAG, "Registering " + number  + " with key " + bytesToHex(identityKey.getPublicKey().serialize()));
        KeyTransparencyClient.updateEntry(KT_URL,number,SIGNAL_APP_ID,identityKey.getPublicKey().serialize(),DEFAULT_AUTHORIZED_PRIVATE_KEY,DEFAULT_AUTHORIZED_PUBLIC_KEY,DEFAULT_RETRY_COUNT);

    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return null;
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
