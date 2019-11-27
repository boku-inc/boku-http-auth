package com.boku.auth.http.client.xml;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import com.boku.auth.http.client.EntityMarshaller;
import com.boku.auth.http.client.BokuAPIClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Converts entities to and from XML using JAX-B. Can be configured in validating or non-validating mode.<br>
 * <br>
 * During integration it may be a good idea to turn on schema validation in order to catch mistakes early.<br>
 * When it comes time to release on production it's usually a good idea to disable schema validation so that
 * non-breaking schema / API changes may be introduced seamlessly.
 */
public class XMLEntityMarshaller implements EntityMarshaller {

    private static final Logger logger = LoggerFactory.getLogger(XMLEntityMarshaller.class);

    private final ConcurrentMap<Class<?>, JAXBContextWrapper> jaxbContexts = new ConcurrentHashMap<>();
    private final boolean validateUnmarshal;
    private final boolean validateMarshal;

    public XMLEntityMarshaller(boolean validateUnmarshal, boolean validateMarshal) {
        this.validateUnmarshal = validateUnmarshal;
        this.validateMarshal = validateMarshal;
    }

    public XMLEntityMarshaller(boolean validateUnmarshal) {
        this.validateUnmarshal = validateUnmarshal;
        this.validateMarshal = false;
    }

    public XMLEntityMarshaller() {
        this.validateUnmarshal = false;
        this.validateMarshal = false;
    }

    @Override
    public String getContentType() {
        return "application/xml";
    }

    @Override
    public String marshal(Object entity) {
        if (entity == null) {
            throw new IllegalArgumentException("Cannot marshal null entity");
        }
        StringWriter sw = new StringWriter();
        try {
            Marshaller m = this.getJAXBContext(entity.getClass()).createMarshaller();
            m.marshal(entity, sw);
        } catch (JAXBException ex) {
            throw new IllegalStateException("Failed to marshal " + entity, ex);
        }
        return sw.toString();
    }

    @Override
    public <T> T unmarshal(Class<T> type, String xml) throws UnmarshalException {
        StringReader sr = new StringReader(xml);
        Object o;
        try {
            Unmarshaller unmarshaller = this.getJAXBContext(type).createUnmarshaller();
            o = unmarshaller.unmarshal(sr);
        } catch (JAXBException ex) {
            logger.error("Failed to parse response XML into {}:\n{}", type, xml, ex);
            throw new UnmarshalException("Failed to parse response", ex);
        }
        if (!type.isAssignableFrom(o.getClass())) {
            logger.error("Response XML not of expected type {}:\n{}", type, xml);
            throw new UnmarshalException("Expected response of " + type + ", but got " + o.getClass());
        }
        @SuppressWarnings("unchecked")
        T ret = (T)o;
        return ret;
    }

    private JAXBContextWrapper getJAXBContext(Class<?> type) throws JAXBException {
        JAXBContextWrapper ret = this.jaxbContexts.get(type);

        if (ret == null) {
            ret = new JAXBContextWrapper(JAXBContext.newInstance(type), this.validateUnmarshal, this.validateMarshal);
            this.jaxbContexts.putIfAbsent(type, ret);
        }

        return ret;
    }

}
