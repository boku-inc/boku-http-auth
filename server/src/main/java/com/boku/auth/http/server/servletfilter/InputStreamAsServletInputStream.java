package com.boku.auth.http.server.servletfilter;

import java.io.IOException;
import java.io.InputStream;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;

/**
 * InputStream delegate, but implements the ServletInputStream interface.
 */
public class InputStreamAsServletInputStream extends ServletInputStream {

    private static final int EOF = -1;

    private final InputStream is;
    private boolean eof = false;

    public InputStreamAsServletInputStream(InputStream is) {
        this.is = is;
    }

    @Override
    public int read() throws IOException {
        int b = is.read();
        if (b == EOF) {
            eof = true;
        }
        return b;
    }

    @Override
    public int read(byte[] b) throws IOException {
        int n = is.read(b);
        if (n == EOF) {
            eof = true;
        }
        return n;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int n = is.read(b, off, len);
        if (n == EOF) {
            eof = true;
        }
        return n;
    }

    @Override
    public long skip(long n) throws IOException {
        return is.skip(n);
    }

    @Override
    public int available() throws IOException {
        return is.available();
    }

    @Override
    public void close() throws IOException {
        is.close();
    }

    @Override
    public void mark(int readlimit) {
        is.mark(readlimit);
    }

    @Override
    public void reset() throws IOException {
        is.reset();
        eof = false;
    }

    @Override
    public boolean markSupported() {
        return is.markSupported();
    }

    @Override
    public boolean isFinished() {
        return eof;
    }

    @Override
    public boolean isReady() {
        try {
            return is.available() > 0;
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public void setReadListener(ReadListener readListener) {
        throw new UnsupportedOperationException();
    }
}
