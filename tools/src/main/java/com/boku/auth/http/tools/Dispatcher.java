package com.boku.auth.http.tools;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;

import static com.boku.auth.http.tools.shared.CmdUtil.*;

/**
 * Main class for executable jar, handles invoking the various separate commands by their name, and returning errors
 * that allow for discoverability.
 *
 * I.e. makes this:
 *
 *     java -jar this.jar check http-request.txt
 *
 * equivalent to this:
 *
 *     java -cp this.jar Check http-request.txt
 */
public class Dispatcher {

    private static final Class<?> ME = Dispatcher.class;
    private static final Class<?>[] COMMANDS = {
        Client.class,
        Server.class,
        Sign.class,
        Check.class,
        Example_BokuAPIClient.class,
        Example_ApacheHttpClient.class,
        Example_ServletServer.class
    };

    public static void main(String[] argv) throws Throwable {
        if (argv.length == 0) {
            usage("No program name specified");
        }

        String name = argv[0];
        argv = Arrays.copyOfRange(argv, 1, argv.length);

        Class<?> mainClass = null;
        for (Class<?> cmd : COMMANDS) {
            if (cmd.getSimpleName().equalsIgnoreCase(name)) {
                mainClass = cmd;
                break;
            }
        }
        if (mainClass == null) {
            try {
                mainClass = Class.forName(ME.getPackage().getName() + "." + name);
            } catch (ClassNotFoundException ignored) {
            }
        }
        if (mainClass == null || mainClass == ME) {
            usage(name + " is not a valid command name");
            return;
        }

        Thread.setDefaultUncaughtExceptionHandler(
            (t, e) -> e.printStackTrace(err)
        );

        run(mainClass, argv);
    }

    private static void run(Class<?> mainClass, String[] argv) throws Throwable {
        Method mainMethod;
        try {
            mainMethod = mainClass.getMethod("main", String[].class);
        } catch (NoSuchMethodException ex) {
            throw new IllegalStateException(mainClass + " does not have a main() method");
        }
        try {
            mainMethod.invoke(null, new Object[] { argv });
        } catch (IllegalAccessException ex) {
            throw new IllegalStateException("Failed to invoke " + mainClass + "'s main() method", ex);
        } catch (InvocationTargetException ex) {
            throw ex.getCause();
        }
    }

    private static void usage(String message) {
        error(message);
        err.println();
        err.println("Usage: " + S0 + " COMMAND [...]");
        err.println("Available commands:");
        err.println();
        for (Class<?> cmd : COMMANDS) {
            String name = cmd.getSimpleName().toLowerCase();
            String synopsis = getStaticString(cmd, "SYNOPSIS");
            err.println(String.format("  %-24s - %s", name, synopsis));
        }
        err.println();
        err.println("Invoke each with no arguments for per-command help.");
        System.exit(1);
    }

    private static String getStaticString(Class<?> cmd, String fieldName) {
        try {
            return (String)cmd.getDeclaredField(fieldName).get(null);
        } catch (IllegalAccessException ex) {
            throw new IllegalStateException(ex);
        } catch (NoSuchFieldException ex) {
            throw new IllegalStateException(fieldName + " missing on " + cmd);
        }
    }

}
