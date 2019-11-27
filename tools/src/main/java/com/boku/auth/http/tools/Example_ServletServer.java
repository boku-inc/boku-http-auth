package com.boku.auth.http.tools;

import com.boku.auth.http.exception.AuthorizationException;
import com.boku.auth.http.keyprovider.PropertiesKeyProvider;
import com.boku.auth.http.tools.shared.ArgvProcessor;
import com.boku.auth.http.tools.shared.GeneralOptions;
import com.boku.auth.http.server.AuthorizationContext;
import com.boku.auth.http.server.AuthorizationContextProvider;
import com.boku.auth.http.server.factory.ServerAuthorizationComponentsFactory;
import com.boku.auth.http.server.servletfilter.BokuHttpAuthFilter;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.EnumSet;
import java.util.Properties;

import static com.boku.auth.http.tools.shared.CmdUtil.*;

/**
 * See {@link #SYNOPSIS}
 */
public class Example_ServletServer {

    public static final String SYNOPSIS = "Example showing how to use BokuHttpAuthFilter and AuthorizationContextProvider to implement server-side authentication";

    public static void main(String[] argv) throws Exception {
        // Parse command line arguments
        ArgvProcessor args = new ArgvProcessor(Example_ServletServer.class, SYNOPSIS, null, argv);
        Server.ServerOptions serverOpts = new Server.ServerOptions();
        args.register(serverOpts);
        GeneralOptions generalOpts = new GeneralOptions();
        args.register(generalOpts);
        while (args.hasNext()) {
            args.usage("Unrecognized extra argument, '" + args.next() + "'");
        }

        // Get root directory for file server
        File root = new File(serverOpts.root).getCanonicalFile();
        if (!root.exists()) {
            die("Specified root " + serverOpts.root + " does not exist");
        }
        if (!root.isDirectory()) {
            die("Specified root " + serverOpts.root + " is not a directory");
        }

        // Load configuration file containing API keys
        Properties config = loadProperties(generalOpts.configFile);
        if (config == null) {
            die("Config file " + generalOpts.configFile + " does not exist");
            return;
        }
        PropertiesKeyProvider propsKeyProvider = new PropertiesKeyProvider(config);

        // Set up auth components
        ServerAuthorizationComponentsFactory factory = new ServerAuthorizationComponentsFactory(propsKeyProvider);
        BokuHttpAuthFilter authFilter = new BokuHttpAuthFilter(
            factory.getThreadLocalServletRequestContextHolder(), factory.getHttpMessageSigner());
        AuthContextCheckingFilter authContextCheckingFilter = new AuthContextCheckingFilter(factory.getAuthorizationContextProvider());

        // We're using Jetty as our server implementation here, but any servlet compliant server should work
        org.eclipse.jetty.server.Server jetty = new org.eclipse.jetty.server.Server(serverOpts.port);
        ServletContextHandler servletHandler = new ServletContextHandler();
        jetty.setHandler(servletHandler);

        // Add the filters to all paths ( /* )
        servletHandler.addFilter(new FilterHolder(authFilter), "/*", EnumSet.allOf(DispatcherType.class));
        servletHandler.addFilter(new FilterHolder(authContextCheckingFilter), "/*", EnumSet.allOf(DispatcherType.class));

        // DefaultServlet can be used to serve files from the filesystem, which is a nice way to test.
        // Obviously don't add this as a handler to your production server.
        DefaultServlet defaultServlet = new DefaultServlet();
        ServletHolder defaultServletHolder = new ServletHolder("default", defaultServlet);
        defaultServletHolder.setInitParameter("resourceBase", root.getAbsolutePath());
        servletHandler.addServlet(defaultServletHolder, "/");

        jetty.start();
        println("Serving files from " + root);
    }

    /**
     * The provided {@link BokuHttpAuthFilter} does not reject unauthorized clients by itself, it just collects
     * the necessary information so that authorization may be checked via {@link AuthorizationContextProvider}.
     * The idea is that you may want handle authorization errors in an application specific way, and you may want to
     * access information such as the partner ID.
     *
     * If you are happy with the behavior of this filter though (it simply returns a HTTP 401), then feel free to copy
     * it into your application - just always make sure both filters run in the correct order, and replace stdout calls
     * with a proper logging framework.
     */
    static class AuthContextCheckingFilter implements Filter {

        private final AuthorizationContextProvider authorizationContextProvider;

        AuthContextCheckingFilter(AuthorizationContextProvider authorizationContextProvider) {
            this.authorizationContextProvider = authorizationContextProvider;
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
            HttpServletRequest httpRequest = (HttpServletRequest)request;
            HttpServletResponse httpResponse = (HttpServletResponse)response;
            AuthorizationContext authContext;
            try {
                authContext = this.authorizationContextProvider.get();
            } catch (AuthorizationException ex) {
                error(ex.getMessage());
                httpResponse.setStatus(HttpStatus.UNAUTHORIZED_401);
                httpResponse.setContentType("text/plain; charset=utf8");
                httpResponse.getOutputStream().println("401 Unauthorized: " + ex.getMessage());
                return;
            }
            // NOTE: In production, you may need to check the partner ID is correct here, e.g. with authContext.assertValidForPartner(...)
            println("Got valid authorization for " + authContext.getAuthorizationHeader().getPartnerId() + " at " + httpRequest.getRequestURI());
            chain.doFilter(request, response);
        }

        @Override
        public void init(FilterConfig filterConfig) {
        }

        @Override
        public void destroy() {
        }
    }

}
