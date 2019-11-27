package com.boku.auth.http.httpmessage;

/**
 * Represents a HTTP request for the purposes of signing.
 */
public final class CanonicalHttpRequest extends CanonicalHttpMessage {

    private String method;
    private String path;
    private String queryString;

    /**
     * HTTP method, such as "GET", "POST", "PUT" and "DELETE"<br>
     * <br>
     * In the example request "GET /a/b/c?x=1&amp;y=test%20val", this would be "GET"
     *
     * @return The HTTP method string. Should not be null.
     */
    public String getMethod() {
        return this.method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    /**
     * The resource path.<br>
     * <br>
     * In the example request "GET /a/b/c?x=1&amp;y=test%20val", this would be "/a/b/c"
     *
     * @return The path string. Should not be null.
     */
    public String getPath() {
        return this.path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    /**
     * The query string as it appears in the request.<br>
     * <br>
     * In the example request "GET /a/b/c?x=1&amp;y=test%20val", this would be "x=1&amp;y=test%20val"
     *
     * @return The query string. May be null if no query string was present in the request.
     */
    public String getQueryString() {
        return this.queryString;
    }

    public void setQueryString(String queryString) {
        this.queryString = queryString;
    }

}
