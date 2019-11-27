package com.boku.auth.http.it.support;

import com.boku.auth.http.httpsigner.HttpMessageSigner;
import com.boku.auth.http.keyprovider.PropertiesKeyProvider;
import com.boku.auth.http.stringsigner.BasicStringSignerImpl;
import com.boku.auth.http.client.BokuAPIClient;
import com.boku.auth.http.client.xml.XMLEntityMarshaller;
import com.boku.auth.http.server.AuthorizationContextProvider;
import org.apache.http.client.HttpClient;
import org.mockito.Mockito;

import com.boku.auth.http.server.servletfilter.BokuHttpAuthFilter;
import com.boku.auth.http.server.servletfilter.BokuHttpAuthFilterCurrentRequestAuthInfoFactory;
import com.boku.auth.http.server.servletfilter.ThreadLocalServletRequestContextHolder;

import java.util.Collections;

public class TestEnvironment {

    public final HttpClient httpClient = HttpClientFactory.create();

    public final HttpMessageSigner httpMessageSigner = Mockito.spy(new HttpMessageSigner(
        new BasicStringSignerImpl(new PropertiesKeyProvider(Collections.singletonMap("boku.auth.keys.bob.1", "abcd1234")))
    ));

    public final BokuAPIClient client = new BokuAPIClient(
        this.httpClient, this.httpMessageSigner, new BriefXMLMarshaller()
    );
    private static class BriefXMLMarshaller extends XMLEntityMarshaller {
        private static final String bloat = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
        @Override
        public String marshal(Object entity) {
            String s = super.marshal(entity);
            if (s.startsWith(bloat)) {
                s = s.substring(bloat.length());
            }
            return s;
        }
    }

    public final ThreadLocalServletRequestContextHolder requestContextHolder = new ThreadLocalServletRequestContextHolder();

    public final AuthorizationContextProvider authContextProvider = new AuthorizationContextProvider(
        new BokuHttpAuthFilterCurrentRequestAuthInfoFactory(this.requestContextHolder),
        this.httpMessageSigner
    );

    public final AuthTestingServer server;

    public TestEnvironment() {
        this.server = new AuthTestingServer(
            new BokuHttpAuthFilter(
                this.requestContextHolder,
                this.httpMessageSigner
            )
        );
    }

    public void shutdown() {
        this.server.stop();
    }

}
