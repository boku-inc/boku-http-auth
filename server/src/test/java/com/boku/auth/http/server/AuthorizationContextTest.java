package com.boku.auth.http.server;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.exception.AuthorizationFailedException;
import com.boku.auth.http.server.AuthorizationContext;
import org.junit.Test;

public class AuthorizationContextTest {

    final AuthorizationContext authContext;

    public AuthorizationContextTest() {
        AuthorizationHeader ah = new AuthorizationHeader();
        ah.setPartnerId("the_merchant");
        this.authContext = new AuthorizationContext(ah);
    }

    @Test
    public void testValid() throws AuthorizationFailedException {
        authContext.assertValidForPartner("the_merchant");
    }

    @Test(expected = AuthorizationFailedException.class)
    public void testInvalid() throws AuthorizationFailedException {
        authContext.assertValidForPartner("le_merchant");
    }

}
