package com.boku.auth.http.it.support;

import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

public class HttpClientFactory {

    public static HttpClient create() {
        PoolingHttpClientConnectionManager connman = new PoolingHttpClientConnectionManager();
        connman.setMaxTotal(1000);
        connman.setDefaultMaxPerRoute(1000);

        RequestConfig requestConfig = RequestConfig.custom()
            .setConnectTimeout(5000)
            .setSocketTimeout(10000)
            .build();

        return HttpClientBuilder.create()
            .setConnectionManager(connman)
            .setDefaultRequestConfig(requestConfig)
            .disableRedirectHandling()
            .build();
    }

}
