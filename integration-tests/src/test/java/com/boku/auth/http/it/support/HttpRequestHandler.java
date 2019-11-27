package com.boku.auth.http.it.support;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface HttpRequestHandler {

    void handle(HttpServletRequest req, HttpServletResponse resp, byte[] requestEntity) throws IOException;

}
