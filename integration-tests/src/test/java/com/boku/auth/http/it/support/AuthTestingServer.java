package com.boku.auth.http.it.support;

import javax.servlet.http.HttpServlet;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.boku.auth.http.server.servletfilter.BokuHttpAuthFilter;

public class AuthTestingServer {

    private static final Logger logger = LoggerFactory.getLogger(AuthTestingServer.class);

    private final Server jetty;
    private final int port;
    private final ServletHandler servletHandler;

    public AuthTestingServer(BokuHttpAuthFilter authFilter) {
        this.jetty = new Server(0);

        this.servletHandler = new ServletHandler();
        servletHandler.addFilterWithMapping(new FilterHolder(authFilter), "/auth/*", 0);

        HandlerCollection handlers = new HandlerCollection();
        handlers.addHandler(servletHandler);
        this.jetty.setHandler(handlers);

        try {
            this.jetty.start();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        this.port = ((ServerConnector)this.jetty.getConnectors()[0]).getLocalPort();
        logger.info("Listening on {}", this.port);
    }

    public void addServlet(String path, HttpServlet servlet) {
        this.servletHandler.addServletWithMapping(new ServletHolder(servlet), path);
    }

    public void stop() {
        try {
            this.jetty.stop();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String getBaseURL() {
        return "http://127.0.0.1:" + this.port;
    }

}
