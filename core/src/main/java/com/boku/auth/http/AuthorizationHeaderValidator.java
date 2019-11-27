package com.boku.auth.http;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/**
 * Simple validator for {@link AuthorizationHeader} objects.
 */
public class AuthorizationHeaderValidator {

    private static final String[] NOT_NULL_FIELD_NAMES = { "scheme", "partnerId", "keyId", "timestamp", "signature" };
    private static final Field[] NOT_NULL_FIELDS;
    static {
        NOT_NULL_FIELDS = new Field[NOT_NULL_FIELD_NAMES.length];
        for (int i = 0; i < NOT_NULL_FIELDS.length; i++) {
            try {
                NOT_NULL_FIELDS[i] = AuthorizationHeader.class.getDeclaredField(NOT_NULL_FIELD_NAMES[i]);
            } catch (NoSuchFieldException ex) {
                throw new IllegalStateException(ex);
            }
            NOT_NULL_FIELDS[i].setAccessible(true);
        }
    }

    /**
     * Get a list of error messages resulting from validating the given {@link AuthorizationHeader}.
     * Returns an empty list if valid.
     */
    public static List<String> getErrors(AuthorizationHeader authHeader) {
        if (authHeader == null) {
            throw new IllegalArgumentException("authHeader cannot be null");
        }
        List<String> ret = new ArrayList<>();
        for (Field field : NOT_NULL_FIELDS) {
            if (fieldValue(field, authHeader) == null) {
                ret.add(field.getName() + ": may not be null");
            }
        }
        return ret;
    }

    private static Object fieldValue(Field f, Object o) {
        try {
            return f.get(o);
        } catch (IllegalAccessException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
