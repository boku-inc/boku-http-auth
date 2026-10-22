package com.boku.auth.http.client.xml;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.annotation.XmlRootElement;

import org.junit.Test;

import com.boku.auth.http.client.EntityMarshaller;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class XMLEntityMarshallerTest {

    @XmlRootElement(name = "payload")
    public static class Payload {
        public String type;
        public Long timestamp;

        public Payload() {
        }

        public Payload(String type, Long timestamp) {
            this.type = type;
            this.timestamp = timestamp;
        }
    }

    @XmlRootElement(name = "animal")
    public static class Animal {
        public String name;
    }

    @XmlRootElement(name = "dog")
    public static class Dog extends Animal {
    }

    private final XMLEntityMarshaller marshaller = new XMLEntityMarshaller();

    @Test
    public void getContentType_always_returnsApplicationXml() {
        assertEquals("application/xml", marshaller.getContentType());
    }

    @Test
    public void unmarshal_marshalledEntity_roundTripsAllValues() throws Exception {
        Payload result = marshaller.unmarshal(Payload.class, marshaller.marshal(new Payload("charge", 1L)));

        assertEquals("charge", result.type);
        assertEquals(Long.valueOf(1L), result.timestamp);
    }

    @Test
    public void unmarshal_malformedXml_throwsUnmarshalExceptionWithoutTheResponseBody() {
        EntityMarshaller.UnmarshalException thrown = assertThrows(EntityMarshaller.UnmarshalException.class,
            () -> marshaller.unmarshal(Payload.class, "this is not xml!"));

        // The body is deliberately kept out of the message and the log (PAY-33366): callers get it from
        // BokuAPIClientException.getResponse().
        assertFalse("message should not include the response body, was: " + thrown.getMessage(),
            thrown.getMessage().contains("this is not xml!"));
        assertTrue(thrown.getCause() instanceof JAXBException);
    }

    @Test
    public void unmarshal_malformedOrUnexpectedXml_logsNothing() throws Exception {
        // slf4j-simple, the test binding, writes ERROR and above to System.err.
        PrintStream originalErr = System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        System.setErr(new PrintStream(captured, true, "UTF-8"));
        try {
            assertThrows(EntityMarshaller.UnmarshalException.class,
                () -> marshaller.unmarshal(Payload.class, "this is not xml!"));
            assertThrows(EntityMarshaller.UnmarshalException.class,
                () -> marshaller.unmarshal(Dog.class, "<animal><name>secret-body-value</name></animal>"));
        } finally {
            System.setErr(originalErr);
        }

        String output = captured.toString("UTF-8");
        assertFalse("nothing should be logged on a parse failure, was: " + output,
            output.contains("this is not xml!") || output.contains("secret-body-value") || output.contains("ERROR"));
    }

    @Test
    public void unmarshal_xmlOfAnotherType_throwsUnmarshalExceptionNamingTheTypesWithoutTheResponseBody() {
        EntityMarshaller.UnmarshalException thrown = assertThrows(EntityMarshaller.UnmarshalException.class,
            () -> marshaller.unmarshal(Dog.class, "<animal><name>secret-body-value</name></animal>"));

        assertTrue("message should name the expected and actual types, was: " + thrown.getMessage(),
            thrown.getMessage().contains(Dog.class.getName()) && thrown.getMessage().contains(Animal.class.getName()));
        assertFalse("message should not include the response body, was: " + thrown.getMessage(),
            thrown.getMessage().contains("secret-body-value"));
    }
}
