package com.boku.util;

/**
 * Simple hex encoder.<br>
 * <br>
 * If you have Apache commons-codec on the classpath, you can replace this with
 * org.apache.commons.codec.binary.Hex
 */
public class HexCodec {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    /**
     * Encode the given byte array as a lower-case hexadecimal string.
     *
     * @param in The data to encode
     * @return The hex encoded string. Does not return null.
     */
    public static String encodeString(byte[] in) {
        char[] hex = new char[in.length * 2];
        for (int i = 0, o = 0; i < in.length; i++) {
            hex[o++] = DIGITS[(0xF0 & in[i]) >>> 4];
            hex[o++] = DIGITS[0x0F & in[i]];
        }
        return new String(hex);
    }

}
