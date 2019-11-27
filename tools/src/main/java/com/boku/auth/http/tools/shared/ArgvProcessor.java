package com.boku.auth.http.tools.shared;

import java.io.PrintStream;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;

import static com.boku.auth.http.tools.shared.CmdUtil.*;

/**
 * Helper for command line argument processing and help output.
 */
public class ArgvProcessor {

    public interface FlagHandler {
        void flag();
    }

    public interface ParamHandler {
        void param(String value);
    }

    private static class Handler {
        final String valueDesc;
        final String description;
        final FlagHandler flagHandler;
        final ParamHandler paramHandler;

        Handler(FlagHandler flagHandler, String description) {
            this.valueDesc = null;
            this.description = description;
            this.flagHandler = flagHandler;
            this.paramHandler = null;
        }

        Handler(String valueDesc, ParamHandler paramHandler, String description) {
            this.valueDesc = valueDesc;
            this.description = description;
            this.flagHandler = null;
            this.paramHandler = paramHandler;
        }
    }

    private final LinkedHashMap<String, Handler> handlers = new LinkedHashMap<>();
    private final LinkedList<Options> optionsList = new LinkedList<>();

    private final String command;
    private final String synopsis;
    private final String bareArgs;
    private final String[] argv;
    private final String[] examples;
    private int i;

    public ArgvProcessor(Class<?> cmd, String synopsis, String bareArgs, String[] argv, String... examples) {
        this.command = cmd.getSimpleName().toLowerCase();
        this.synopsis = synopsis;
        this.bareArgs = bareArgs;
        this.argv = argv;
        this.examples = examples;
    }

    public void register(Options options) {
        options.register(this);
        optionsList.add(options);
    }

    public void addFlag(String name, FlagHandler handler, String description) {
        if (this.handlers.put(name, new Handler(handler, description)) != null) {
            throw new IllegalStateException("Arg " + name + " declared twice");
        }
    }

    public void addParam(String name, String valueDesc, ParamHandler handler, String description) {
        if (this.handlers.put(name, new Handler(valueDesc, handler, description)) != null) {
            throw new IllegalStateException("Arg " + name + " declared twice");
        }
    }

    public void usage(String message) {
        err.println("Input error: " + message);
        err.println();
        printUsage();
        System.exit(1);
    }

    private void printUsage() {
        PrintStream out = err;
        out.println("Usage: " + S0 + " " + command + " [OPTION ...] " + (bareArgs == null ? "" : bareArgs));
        if (synopsis != null) {
            out.println("Synopsis: " + synopsis);
        }
        out.println("Options:");
        out.println();

        int maxOptWidth = 1;
        for (Map.Entry<String, Handler> e : this.handlers.entrySet()) {
            int len = e.getKey().length();
            if (e.getValue().valueDesc != null) {
                len += 1 + e.getValue().valueDesc.length();
            }
            if (len > maxOptWidth) {
                maxOptWidth = len;
            }
        }
        String fmt = "  -%-" + maxOptWidth + "s  %s";
        for (Map.Entry<String, Handler> e : this.handlers.entrySet()) {
            String left;
            if (e.getValue().valueDesc == null) {
                left = e.getKey();
            } else {
                left = e.getKey() + " " + e.getValue().valueDesc;
            }
            out.println(String.format(fmt, left, e.getValue().description));
        }
        out.println();

        if (this.examples.length > 0) {
            out.println("Examples:");
            out.println();
            for (String example : this.examples) {
                out.println("    " + example.replace("$0", S0 + ' ' + command));
            }
            out.println();
        }
    }

    private void loop() {
        for (; i < argv.length; i++) {
            if (argv[i].length() < 2 || argv[i].charAt(0) != '-') {
                return;
            }
            String name = argv[i].substring(1);
            Handler handler = this.handlers.get(name);
            if (handler == null) {
                usage("Unrecognized flag, " + argv[i]);
                return;
            }

            if (handler.flagHandler != null) {
                handler.flagHandler.flag();
            } else if (handler.paramHandler != null) {
                i++;
                if (i >= argv.length) {
                    usage("flag " + argv[i - 1] + " requires argument");
                }
                try {
                    handler.paramHandler.param(argv[i]);
                } catch (IllegalArgumentException ex) {
                    usage("flag " + argv[i - 1] + " value invalid: " + ex.getMessage());
                }
            } else {
                throw new IllegalStateException();
            }
        }
    }

    public boolean hasNext() {
        loop();
        if (i < argv.length) {
            return true;
        }
        for (Options options : optionsList) {
            options.finish(this);
        }
        return false;
    }

    public String next() {
        loop();
        return argv[i++];
    }
}
