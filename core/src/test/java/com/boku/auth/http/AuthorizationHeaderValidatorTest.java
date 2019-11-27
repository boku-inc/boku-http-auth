package com.boku.auth.http;

import java.util.Iterator;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

public class AuthorizationHeaderValidatorTest {

    @Test
    public void testValid() {
        AuthorizationHeader ah = new AuthorizationHeader();
        ah.setScheme("TEST");
        ah.setPartnerId("bob");
        ah.setKeyId("1");
        ah.setTimestamp(System.currentTimeMillis() / 1000);
        ah.setSignature("VALID_SIGNATURE");

        List<String> errors = AuthorizationHeaderValidator.getErrors(ah);
        Assert.assertNotNull(errors);
        Assert.assertEquals(0, errors.size());
    }

    @Test
    public void testInvalid() {
        List<String> errors = AuthorizationHeaderValidator.getErrors(new AuthorizationHeader());
        Assert.assertNotNull(errors);
        Iterator<String> itr = errors.iterator();
        Assert.assertEquals("scheme: may not be null", itr.next());
        Assert.assertEquals("partnerId: may not be null", itr.next());
        Assert.assertEquals("keyId: may not be null", itr.next());
        Assert.assertEquals("timestamp: may not be null", itr.next());
        Assert.assertEquals("signature: may not be null", itr.next());
        Assert.assertFalse(itr.hasNext());
    }
}
