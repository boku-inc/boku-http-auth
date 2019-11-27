package com.boku.auth.http.httpmessage;

import java.util.Objects;

/**
 * Simple HTTP header representation used with {@link CanonicalHttpMessage}.
 */
public class CanonicalHttpHeader {

    private String name;
    private String value;

    public CanonicalHttpHeader() {
    }

    public CanonicalHttpHeader(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CanonicalHttpHeader that = (CanonicalHttpHeader)o;
        return Objects.equals(name, that.name) &&
            Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, value);
    }
}
