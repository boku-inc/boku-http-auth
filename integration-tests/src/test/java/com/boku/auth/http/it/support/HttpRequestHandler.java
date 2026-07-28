package com.boku.auth.http.it.support;

import java.io.IOException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface HttpRequestHandler {

    void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException;

}
