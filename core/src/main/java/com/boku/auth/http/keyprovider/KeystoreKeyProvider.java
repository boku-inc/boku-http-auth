package com.boku.auth.http.keyprovider;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

/**
 * Implements {@link KeyProvider} by looking up the requested keys as passwords stored in a Java KeyStore.<br>
 * Loading from PKCS12 files is supported, other formats may or may not work.<br>
 * <br>
 * Keys are expected to exist with aliases in the form of `$partnerId.$keyId`.<br>
 * Assuming your partner-id is "abc" and you want to store a key with ID "1", you can generate a compatible P12 file as
 * follows:<br>
 * <br>
 * <pre>keytool -importpass -storetype pkcs12 -alias abc.1 -keystore filename.p12</pre>
 * <br>
 * When prompted for the keystore password, enter your desired keystore password, and when prompted for the password
 * to save, paste in the API key that was provided to you.
 */
public class KeystoreKeyProvider implements KeyProvider {

    private final KeyStore.PasswordProtection keystorePassword;
    private final KeyStore keyStore;
    private final SecretKeyFactory keyFactory;

    /**
     * Create a key provider backed by a pre-loaded KeyStore.
     *
     * @param keyStore The KeyStore instance
     * @param password The KeyStore password, required to access individual entries
     */
    public KeystoreKeyProvider(KeyStore keyStore, String password) {
        this.keystorePassword = new KeyStore.PasswordProtection(password.toCharArray());
        this.keyStore = keyStore;

        try {
            this.keyFactory = SecretKeyFactory.getInstance("PBE");
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("No PBE (password based encryption) support?", ex);
        }
    }

    /**
     * Create a key provider backed by the given PKCS12 (.p12) file.
     *
     * @param filename The path to the p12 file on the filesystem
     * @param password The keystore password, required to open the file and access individual entries
     * @return A {@link KeystoreKeyProvider} instance. Does not return null.
     * @throws IOException If there was an IO error loading the file.
     */
    public static KeystoreKeyProvider fromPKCS12(String filename, String password) throws IOException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException ex) {
            throw new IllegalStateException("No P12 support?", ex);
        }

        try {
            keyStore.load(new FileInputStream(filename), password.toCharArray());
        } catch (NoSuchAlgorithmException | CertificateException ex) {
            throw new IllegalStateException("Error loading " + filename, ex);
        }

        return new KeystoreKeyProvider(keyStore, password);
    }

    @Override
    public synchronized String get(String partnerId, String keyId) {
        String alias = partnerId + "." + keyId;
        KeyStore.SecretKeyEntry entry;
        try {
            entry = (KeyStore.SecretKeyEntry)this.keyStore.getEntry(alias, this.keystorePassword);
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException ex) {
            throw new IllegalStateException("Failed to load " + alias + ": " + ex.getMessage(), ex);
        }
        if (entry == null) {
            return null;
        }

        PBEKeySpec keySpec;
        try {
            keySpec = (PBEKeySpec)this.keyFactory.getKeySpec(entry.getSecretKey(), PBEKeySpec.class);
        } catch (InvalidKeySpecException ex) {
            throw new IllegalStateException(ex);
        }

        return new String(keySpec.getPassword());
    }

}
