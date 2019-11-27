package com.boku.auth.http.client.xml;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.SchemaOutputResolver;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.ValidationEvent;
import javax.xml.bind.ValidationEventHandler;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

/**
 * Simple wrapper for JAXBContext that can return validating instances of {@link Marshaller} and {@link Unmarshaller}
 * by default.
 */
public class JAXBContextWrapper {

    private final JAXBContext jaxbContext;
    private final Schema schema;
    private final boolean validatingUnmarshaller;
    private final boolean validatingMarshaller;

    public JAXBContextWrapper(JAXBContext jaxbContext, boolean validatingUnmarshaller, boolean validatingMarshaller) {
        this.jaxbContext = jaxbContext;
        if (validatingMarshaller || validatingUnmarshaller) {
            this.schema = generateSchema(this.jaxbContext);
        } else {
            this.schema = null;
        }
        this.validatingUnmarshaller = validatingUnmarshaller;
        this.validatingMarshaller = validatingMarshaller;
    }

    public Unmarshaller createUnmarshaller() throws JAXBException {
        Unmarshaller um = this.jaxbContext.createUnmarshaller();
        if (this.validatingUnmarshaller) {
            um.setEventHandler(new StrictValidationEventHandler());
            um.setSchema(this.schema);
        }
        return um;
    }

    public Marshaller createMarshaller() throws JAXBException {
        Marshaller m = this.jaxbContext.createMarshaller();
        if (this.validatingMarshaller) {
            m.setEventHandler(new StrictValidationEventHandler());
            m.setSchema(this.schema);
        }
        return m;
    }

    private static Schema generateSchema(JAXBContext jaxbContext) {
        StringSchemaOutputResolver sor = new StringSchemaOutputResolver();
        try {
            jaxbContext.generateSchema(sor);
        }
        catch(IOException ex) {
            throw new RuntimeException("Failed to generate schema from JAXBContext", ex);
        }

        SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        try {
            return sf.newSchema(sor.getSchemaSource());
        }
        catch(SAXException ex) {
            throw new RuntimeException("Failed to import schema", ex);
        }
    }

    public static class StrictValidationEventHandler implements ValidationEventHandler {

        @Override
        public boolean handleEvent(ValidationEvent event) {
            return false;
        }
    }

    public static class StringSchemaOutputResolver extends SchemaOutputResolver {

        private final StringWriter sw = new StringWriter();

        @Override
        public Result createOutput(String namespaceUri, String suggestedFileName) {
            StreamResult sr = new StreamResult(sw);
            sr.setSystemId(namespaceUri);
            return sr;
        }

        @Override
        public String toString() {
            return sw.toString();
        }

        public Source getSchemaSource() {
            return new StreamSource(new StringReader(this.toString()));
        }
    }

}
