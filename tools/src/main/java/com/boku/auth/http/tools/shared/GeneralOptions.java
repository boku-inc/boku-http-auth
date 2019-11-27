package com.boku.auth.http.tools.shared;

/**
 * Generic options common to most commands
 */
public class GeneralOptions implements Options {

    public String configFile = "config.properties";
    public String indent = "    | ";
    public boolean verbose = true;

    @Override
    public void register(ArgvProcessor args) {
        args.addParam(
            "config", "<FILE>",
            value -> configFile = value,
            "Use specified config file instead of default " + configFile
        );
        args.addFlag(
            "quiet",
            () -> verbose = false,
            "Do not print intermediate debugging information, such as raw HTTP requests or signature input"
        );
        args.addFlag(
            "no-indent",
            () -> indent = "",
            "Don't indent the debugging output (makes for easier copy/paste.)"
        );
        args.addFlag(
            "show-line-endings",
            () -> CmdUtil.showLineEndings = true,
            "When indenting output, also print line endings as the ¶ symbol. This helps distinguish trailing newline vs not."
        );
    }

}
