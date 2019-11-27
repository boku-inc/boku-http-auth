package com.boku.auth.http.client;

/**
 * Plugged into {@link BokuAPIClient} at construct time to allow marshalling of requests/responses to and from a
 * specific format.
 */
public interface EntityMarshaller {

    @SuppressWarnings("serial")
    class UnmarshalException extends Exception {
        public UnmarshalException(String message, Throwable cause) {
            super(message, cause);
        }
        public UnmarshalException(String message) {
            super(message);
        }
    }

    /**
     * The Content-Type this marshaller produces, such as 'application/xml' or 'application/json'.<br>
     * <br>
     * The returned type should not contain parameters - a parameter indicating the charset will be added by
     * {@link BokuAPIClient} based on the request charset.
     */
    String getContentType();

    String marshal(Object entity);

    <T> T unmarshal(Class<T> type, String entityString) throws UnmarshalException;

}
