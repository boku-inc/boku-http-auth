package com.boku.auth.http.it;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.it.support.TestEnvironment;
import org.junit.After;

public abstract class CWAIntegrationTestBase {

    final TestEnvironment env = new TestEnvironment();

    @After
    public void cleanup() {
        this.env.shutdown();
    }

    public String url(String path) {
        return this.env.server.getBaseURL() + path;
    }

    public AuthorizationHeader authorization(String ...signedHeaders) {
        AuthorizationHeader ah = new AuthorizationHeader();
        ah.setPartnerId("bob");
        ah.setKeyId("1");
        for (String sh : signedHeaders) {
            ah.getSignedHeaders().add(sh);
        }
        return ah;
    }

}
