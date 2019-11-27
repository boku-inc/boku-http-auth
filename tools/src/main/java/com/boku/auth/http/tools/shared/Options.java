package com.boku.auth.http.tools.shared;

/**
 * Group of command line options, used with {@link ArgvProcessor}
 */
public interface Options {

    /**
     * Called by {@link ArgvProcessor#register}, during which you should register individual arguments.
     */
    void register(ArgvProcessor args);

    /**
     * Called once argument processing is complete to perform any post initialization.
     */
    default void finish(ArgvProcessor args) {
    }

}
