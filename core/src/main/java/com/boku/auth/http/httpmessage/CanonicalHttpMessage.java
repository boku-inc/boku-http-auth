package com.boku.auth.http.httpmessage;

import java.util.ArrayList;
import java.util.List;

/**
 * Elements common to HTTP requests and responses.
 */
public abstract class CanonicalHttpMessage {

    private List<CanonicalHttpHeader> headers = new ArrayList<>();

    private String entityDigest;

    /**
     * An ordered list of header names and values that have or will be included in the signature.
     *
     * @return The list of headers. May be empty, does not return null.
     */
    public List<CanonicalHttpHeader> getHeaders() {
        return this.headers;
    }

    public void setHeaders(List<CanonicalHttpHeader> headers) {
        this.headers = headers;
    }

    /**
     * The hex encoded digest of the message entity, or null if there was no entity.
     *
     * @return The entity digest string, or null if there was no entity.
     */
    public String getEntityDigest() {
        return this.entityDigest;
    }

    public void setEntityDigest(String entityDigest) {
        this.entityDigest = entityDigest;
    }

    @Override
    public String toString() {
        return this.toString(new StringBuilder()).toString();
    }

    /**
     * Implements constructing a string Message To Sign, excluding the current timestamp which must be appended to the
     * produced string before signing.<br>
     * <br>
     * Note that this method implements both request and response in one place, and so does not need to be overridden
     * and extended by the sub-classes.
     *
     * @param out The StringBuilder to append the output of this method to
     * @return the same StringBuilder that was passed in as the `out` parameter (for method chaining)
     */
    public StringBuilder toString(StringBuilder out) {
        if (this instanceof CanonicalHttpRequest) {
            CanonicalHttpRequest httpRequest = (CanonicalHttpRequest)this;
            out.append(httpRequest.getMethod());
            out.append(' ');
            out.append(httpRequest.getPath());
            if (httpRequest.getQueryString() != null) {
                out.append('?');
                out.append(httpRequest.getQueryString());
            }
            out.append('\n');
        }

        for (CanonicalHttpHeader hdr : this.getHeaders()) {
            out.append(hdr.getName());
            out.append(": ");
            out.append(hdr.getValue());
            out.append('\n');
        }

        if (this.getEntityDigest() != null) {
            out.append(this.getEntityDigest());
        }
        out.append('\n');

        return out;
    }
}
