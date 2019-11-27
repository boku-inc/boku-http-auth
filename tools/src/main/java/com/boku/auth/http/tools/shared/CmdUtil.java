package com.boku.auth.http.tools.shared;

import com.boku.util.IO;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Properties;

/**
 * Quick and dirty util functions for the command line tools, mostly IO.
 */
public final class CmdUtil {

    /**
     * Self name. Equivalent to bash $0, C argv[0], etc
     */
    public static final String S0;
    static {
        File jarFile = new File(CmdUtil.class.getProtectionDomain()
            .getCodeSource()
            .getLocation()
            .getPath())
            .getAbsoluteFile();
        String jar = jarFile.getName();
        try {
            String pwd = new File(".").getCanonicalPath() + '/';
            if (jarFile.getPath().startsWith(pwd)) {
                jar = jarFile.getPath().substring(pwd.length());
            }
        } catch (IOException ignored) {
        }
        S0 = "java -jar " + jar;
    }

    public static PrintStream err = System.err;
    public static PrintStream out = System.out;

    public static void die(String message) {
        err.println("ERROR: " + message);
        out.flush();
        err.flush();
        System.exit(1);
    }

    public static void warn(String message) {
        err.println("WARN: " + message);
    }
    public static void error(String message) {
        err.println("ERROR: " + message);
    }

    public static void println(Object... va) {
        for (Object o : va) {
            out.print(o);
        }
        out.println();
    }

    public static boolean showLineEndings = false;

    public static String indent(String indent, String in) {
        if (indent.length() == 0) {
            return in;
        }
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (true) {
            int j = in.indexOf('\n', i);
            if (j < 0) {
                if (i < in.length()) {
                    out.append(indent).append(in.substring(i));
                }
                break;
            }
            j++;
            out.append(indent).append(in, i, j - 1);
            if (showLineEndings) {
                out.append('¶');
            }
            out.append('\n');
            i = j;
        }
        return out.toString();
    }

    public static byte[] load(String filename) throws IOException {
        if ("-".equals(filename)) {
            return IO.toByteArray(System.in);
        }
        FileInputStream is = getFileInputStream(filename);
        if (is == null) {
            die("File '" + filename + "' does not exist");
            throw new IllegalStateException();
        }
        try {
            return IO.toByteArray(is);
        } finally {
            is.close();
        }
    }

    public static Properties loadProperties(String filename) {
        FileInputStream is = getFileInputStream(filename);
        if (is == null) {
            return null;
        }
        Properties ret = new Properties();
        try {
            ret.load(is);
        } catch (IOException ex) {
            throw new IllegalStateException("Error loading properties file " + filename, ex);
        }
        return ret;
    }

    private CmdUtil() {}

    private static FileInputStream getFileInputStream(String filename) {
        try {
            return new FileInputStream(filename);
        } catch (FileNotFoundException ex) {
            return null;
        }
    }
}
