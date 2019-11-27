package com.boku.auth.http.keyprovider;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Properties;

/**
 * Implements {@link KeyProvider} by looking up the requested keys in a properties file.<br>
 * <br>
 * It looks for properties in the format `boku.auth.keys.$partnerId.$keyId`, and expects the value to be the key string
 * itself.<br>
 * <br>
 * Note that although easy to use, it may not be entirely sensible to store key data in a plain text file on the
 * filesystem such as this.
 * Consider instead using a custom KeyProvider implementation that retrieves values from a more secure source, or using
 * the provided {@link KeystoreKeyProvider} which can use a protected PKCS12 keystore.
 */
public class PropertiesKeyProvider implements KeyProvider {

    private static final String PREFIX = "boku.auth.keys";

    private final Properties properties;
    private final String[] defaultPartnerKeyId;

    /**
     * Create a new instance using the given properties
     *
     * @param properties A pre-populated instance of {@link Properties}
     * @throws IllegalStateException If the properties instance contains no valid key entries
     */
    public PropertiesKeyProvider(Properties properties) {
        this.properties = properties;
        this.defaultPartnerKeyId = getDefaultPartnerAndKeyId(properties);
    }

    /**
     * Create a new instance using properties loaded from the given file.
     *
     * @param filename The path to a properties file that exists on the local filesystem
     * @throws FileNotFoundException If the referenced file does not exist
     * @throws IllegalStateException If the file contains no valid key entries
     */
    public static PropertiesKeyProvider fromFile(String filename) throws FileNotFoundException {
        FileInputStream is = new FileInputStream(filename);
        Properties props = new Properties();
        try {
            props.load(is);
        } catch (IOException ex) {
            throw new IllegalStateException("Error loading properties file " + filename, ex);
        }
        return new PropertiesKeyProvider(props);
    }

    /**
     * Create a new instance using properties loaded from the given file located on the classpath.
     *
     * @param filename The path to a properties file that exists on the local filesystem
     * @throws FileNotFoundException If the referenced file does not exist
     * @throws IllegalStateException If the file contains no valid key entries
     */
    public static PropertiesKeyProvider fromClasspath(String filename) throws FileNotFoundException {
        InputStream is = PropertiesKeyProvider.class.getResourceAsStream(filename);
        if (is == null) {
            throw new FileNotFoundException(filename + " not found on the classpath");
        }
        Properties props = new Properties();
        try {
            props.load(is);
        } catch (IOException ex) {
            throw new IllegalStateException("Error loading properties file " + filename, ex);
        }
        return new PropertiesKeyProvider(props);
    }

    /**
     * Like {@link #PropertiesKeyProvider(Properties)}, but uses values from the given map.
     *
     * @param map The map from which to populate the properties
     */
    public PropertiesKeyProvider(Map<String, String> map) {
        this(toProperties(map));
    }

    @Override
    public String get(String partnerId, String keyId) {
        return this.properties.getProperty(PREFIX + "." + partnerId + "." + keyId);
    }

    /**
     * Return the partner ID and key ID of the default key in the supplied properties.<br>
     * <br>
     * The default is determined via either an entry in the form `boku.auth.keys.default=$partnerId.$keyId`, or if that
     * is not present, simply the first key entry found.<br>
     * NOTE: since Properties are unordered, the 'first' key is not deterministic unless you only have one key in the
     * file.
     *
     * @return A 2 element array, where [0] is the partner ID and [1] is the key ID.
     */
    public String[] getDefaultPartnerKeyId() {
        return this.defaultPartnerKeyId;
    }

    private static String[] getDefaultPartnerAndKeyId(Properties config)  {
        String def = config.getProperty(PREFIX + ".default");
        if (def == null) {
            for (String key : config.stringPropertyNames()) {
                if (key.startsWith(PREFIX + ".")) {
                    def = key;
                    break;
                }
            }
            if (def == null) {
                throw new IllegalStateException("No `" + PREFIX + "` defined in config");
            }
        } else {
            def = PREFIX + "." + def;
        }

        String[] part = def.split("\\.");
        if (part.length != 5) {
            throw new IllegalStateException("Invalid property name format, " + def);
        }
        return new String[]{part[3], part[4]};

    }

    @SuppressWarnings("UseOfPropertiesAsHashtable")
    private static Properties toProperties(Map<String, String> map) {
        Properties props = new Properties();
        props.putAll(map);
        return props;
    }
}
