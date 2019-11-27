package com.boku.auth.http.client;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import com.boku.auth.http.client.exception.BokuAPIClientException;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.entity.ContentType;

import com.boku.auth.http.client.exception.InvalidAPIEntityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Representation of HTTP response + entity, which may be returned by
 * {@link BokuAPIClient.RequestBuilder#execute(Class)}.<br>
 * If you just need access to the unmarshalled response contents, instead pass the entity class directly into the
 * execute method.<br>
 * If you need access full response information including headers, the entity of a HTTP error response, etc, use this
 * instead.<br>
 * Once you have the BokuAPIClientResponse object, you may still get the unmarshalled form by calling
 * {@link Entity#getDataAs(Class)}.
 */
public final class BokuAPIClientResponse {

    private static final Logger logger = LoggerFactory.getLogger(BokuAPIClientResponse.class);

    private final EntityMarshaller entityMarshaller;

    private final HttpResponse httpResponse;
    private final Entity entity;

    BokuAPIClientResponse(EntityMarshaller entityMarshaller, HttpResponse httpResponse, ContentType entityContentType, byte[] entityData) {
        this.entityMarshaller = entityMarshaller;
        this.httpResponse = httpResponse;
        if (entityData == null) {
            this.entity = null;
        } else {
            this.entity = new Entity(entityContentType, entityData);
        }
    }

    /**
     * @see HttpResponse#getStatusLine()
     */
    public StatusLine getStatusLine() {
        return this.httpResponse.getStatusLine();
    }

    /**
     * @see HttpResponse#containsHeader(String)
     */
    public boolean containsHeader(String name) {
        return this.httpResponse.containsHeader(name);
    }

    /**
     * @see HttpResponse#getHeaders(String)
     */
    public Header[] getHeaders(String name) {
        return this.httpResponse.getHeaders(name);
    }

    /**
     * @see HttpResponse#getFirstHeader(String)
     */
    public Header getFirstHeader(String name) {
        return this.httpResponse.getFirstHeader(name);
    }

    /**
     * @see HttpResponse#getLastHeader(String)
     */
    public Header getLastHeader(String name) {
        return this.httpResponse.getLastHeader(name);
    }

    /**
     * @see HttpResponse#getAllHeaders()
     */
    public Header[] getAllHeaders() {
        return this.httpResponse.getAllHeaders();
    }

    /**
     * Get the {@link Entity} returned with this response, if any.
     *
     * @return The entity, or null if none.
     */
    public Entity getEntity() {
        return this.entity;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(this.getStatusLine().toString());
        for (Header header : this.getAllHeaders()) {
            sb.append('\n').append(header.getName()).append(": ").append(header.getValue());
        }
        if (this.entity != null) {
            sb.append("\n\n");
            if (this.entity.isText()) {
                sb.append(this.entity.getDataAsText());
            } else {
                sb.append("(entity ").append(this.entity.getData().length).append(" bytes)");
            }
        }
        return sb.toString();
    }

    /**
     * In-memory HTTP entity, accesses do not trigger network reads - that has already been done.<br>
     * Assuming you don't care about streaming results etc, slightly easier to work with than a raw HttpResponse.<br>
     * <br>
     * Allows access to the raw data, text form, and unmarshalled form, if available.
     */
    public class Entity {

        private final ContentType contentType;
        private final byte[] data;

        private String cachedString = null;

        Entity(ContentType contentType, byte[] data) {
            if (contentType == null || data == null) {
                throw new IllegalStateException("contentType or data cannot be null");
            }
            this.contentType = contentType;
            this.data = data;
        }

        /**
         * The Content-Type associated with the entity, or application/octet-stream if none was given.
         */
        public ContentType getContentType() {
            return this.contentType;
        }

        /**
         * The charset (i.e. character encoding) of the entity, assuming it is a text type, or null otherwise.
         */
        public Charset getCharset() {
            return this.contentType.getCharset();
        }

        /**
         * Raw entity data.<br>
         * Never null.
         */
        public byte[] getData() {
            return this.data;
        }

        /**
         * Returns true if the entity is a text type and has a {@link #getCharset() charset} specified.<br>
         * <br>
         * Note that this will return false if the Content-Type header does not specify a charset, even for text types.
         * If you need an isText check that works independent of charset, please create your own whitelist of text types
         * and test against that instead.
         */
        public boolean isText() {
            return this.getCharset() != null;
        }

        /**
         * Return the entity data decoded as text into a {@link String}.<br>
         * <br>
         * If the Content-Type is not text, may return garbage.
         */
        public String getDataAsText() {
            if (this.cachedString != null) {
                return this.cachedString;
            }

            Charset cs = this.getCharset();
            if (cs == null) {
                cs = StandardCharsets.UTF_8;
                logger.warn("Content-Type [{}] does not specify a charset, defaulting to {}! This may result in text " +
                        "being processed incorrectly, consider fixing the responding server.", this.contentType, cs);
            }

            this.cachedString = new String(this.data, cs);

            return this.cachedString;
        }

        /**
         * Get the response entity unmarshalled into the given class.
         *
         * @param entityClass The class which the unmarshaller should be able to map the response entity text onto
         * @param <T> Type of entityClass
         * @return An instance of T
         * @throws BokuAPIClientException If unmarshalling failed for any reason
         */
        public <T> T getDataAs(Class<T> entityClass) throws BokuAPIClientException {
            if (entityClass == String.class) {
                @SuppressWarnings("unchecked")
                T ret = (T)this.getDataAsText();
                return ret;
            }

            if (entityMarshaller == null) {
                throw new IllegalStateException("Cannot unmarshal response entity, no EntityMarshaller supplied");
            }
            try {
                return entityMarshaller.unmarshal(entityClass, this.getDataAsText());
            } catch (EntityMarshaller.UnmarshalException ex) {
                throw new InvalidAPIEntityException(ex.getMessage(), BokuAPIClientResponse.this, ex);
            }
        }

        @Override
        public String toString() {
            if (this.isText()) {
                return this.contentType + "[" + this.getDataAsText() + "]";
            }
            return this.contentType + "(" + this.data.length + " bytes)";
        }
    }
}
