package com.boku.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * IO related utility functions.<br>
 * <br>
 * If you have Apache commons-io on the classpath, you can replace this with org.apache.commons.io.IOUtils.
 */
public class IO {

    /**
     * Fully read the contents of the given InputStream and return the result in a byte array.<br>
     * <br>
     * NOTE: no limits are placed on the amount of data read, so this method should not be used in a production
     * scenario unless the size of the input is known or limited via other means.
     *
     * @param is The stream to read
     * @return byte array containing data read from the stream. May be empty, does not return null.
     */
    public static byte[] toByteArray(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) {
            baos.write(buf, 0, n);
        }
        return baos.toByteArray();
    }

}
