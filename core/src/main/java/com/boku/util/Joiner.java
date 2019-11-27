package com.boku.util;

/**
 * Basic String joining functionality
 */
public class Joiner {

    /**
     * Equivalent to {@link String#join(CharSequence, Iterable)} but appends to an existing StringBuilder.
     *
     * @param sb the {@link StringBuilder} to append the result of this call to
     * @param delimiter a string placed between each set of values to separate them
     * @param iterable an iterable which will be drained giving the values to join
     */
    public static StringBuilder join(StringBuilder sb, String delimiter, Iterable<?> iterable) {
        int i = 0;
        for (Object o : iterable) {
            if (i++ > 0) {
                sb.append(delimiter);
            }
            sb.append(o);
        }
        return sb;
    }

    /**
     * Equivalent to Java 8 {@link String#join(CharSequence, Iterable)}
     *
     * @param delimiter a string placed between each set of values to separate them
     * @param iterable an iterable which will be drained giving the values to join
     */
    public static String join(String delimiter, Iterable<?> iterable) {
        return join(new StringBuilder(), delimiter, iterable).toString();
    }

}
