package com.boku.auth.http.server.factory;

import com.boku.auth.http.keyprovider.KeystoreKeyProvider;
import com.boku.auth.http.server.servletfilter.BokuHttpAuthFilter;
import com.boku.auth.http.server.servletfilter.BokuHttpAuthFilterCurrentRequestAuthInfoFactory;
import com.boku.auth.http.httpsigner.HttpMessageSigner;
import com.boku.auth.http.keyprovider.KeyProvider;
import com.boku.auth.http.stringsigner.BasicStringSignerImpl;
import com.boku.auth.http.stringsigner.StringSigner;
import com.boku.auth.http.server.AuthorizationContextProvider;
import com.boku.auth.http.server.servletfilter.ThreadLocalServletRequestContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Map;
import java.util.Properties;

/**
 * Factory for server side auth components.<br>
 * <br>
 * The server components {@link BokuHttpAuthFilter} and {@link AuthorizationContextProvider} must share state, and so
 * must be wired up correctly with the same common dependencies. This class helps you do that correctly.<br>
 * <br>
 * There are two ways this factory may be used:<ul>
 *     <li>Instanced (RECOMMENDED): create a new instance of this class using the constructor arguments to configure it
 *     correctly, e.g. to pass your custom {@link KeyProvider}, and then use the various accessors to get instances of
 *     the various components to wire into your app.</li>
 *     <li>Static: configure the factory via system properties or init-params passed to {@link BokuHttpAuthFilter}, and
 *     then use the static instance accessible via {@link #getInstance()}.<br>NOTE: you must set the configuration
 *     parameters before {@link #getInstance()} is called for the first time or they will have no effect!
 *     See documentation on {@link BokuHttpAuthFilter#init} for details of configuration parameters.</li>
 * </ul>
 */
public class ServerAuthorizationComponentsFactory {

    public static final String KEYPROVIDER_TYPE_PKCS12 = "PKCS12";
    public static final String KEYPROVIDER_TYPE_CUSTOM = "custom";

    public static final String KEYPROVIDER_TYPE_KEY = "com.boku.auth.keyprovider.type";
    public static final String KEYPROVIDER_TYPE_DEFAULT = KEYPROVIDER_TYPE_PKCS12;

    public static final String KEYPROVIDER_P12_FILE_KEY = "com.boku.auth.keyprovider.pkcs12.file";
    public static final String KEYPROVIDER_P12_FILE_DEFAULT = "boku-auth-keys.p12";
    public static final String KEYPROVIDER_P12_PASSWORD_KEY = "com.boku.auth.keyprovider.pkcs12.password";

    public static final String KEYPROVIDER_CUSTOM_FACTORY_METHOD_KEY = "com.boku.auth.keyprovider.custom.factory-method";

    private static final Logger logger = LoggerFactory.getLogger(ServerAuthorizationComponentsFactory.class);

    private static ServerAuthorizationComponentsFactory INSTANCE;

    /**
     * Get the static instance of {@link ServerAuthorizationComponentsFactory}, initializing if necessary.<br>
     * See class-level docs for details.
     */
    public synchronized static ServerAuthorizationComponentsFactory getInstance() {
        if (INSTANCE == null) {
            INSTANCE = createDefaultInstance();
        }
        return INSTANCE;
    }

    private final HttpMessageSigner httpMessageSigner;
    private final ThreadLocalServletRequestContextHolder threadLocalServletRequestContextHolder;
    private final AuthorizationContextProvider authorizationContextProvider;

    /**
     * Wire up server components using the regular {@link BasicStringSignerImpl} and your given {@link KeyProvider}
     * implementation.
     */
    public ServerAuthorizationComponentsFactory(KeyProvider keyProvider) {
        this(new BasicStringSignerImpl(keyProvider));
    }

    /**
     * Wire up server components using a custom {@link StringSigner} implementation.
     */
    public ServerAuthorizationComponentsFactory(StringSigner stringSigner) {
        this.httpMessageSigner = new HttpMessageSigner(stringSigner);
        this.threadLocalServletRequestContextHolder = new ThreadLocalServletRequestContextHolder();
        this.authorizationContextProvider = new AuthorizationContextProvider(
            new BokuHttpAuthFilterCurrentRequestAuthInfoFactory(this.threadLocalServletRequestContextHolder),
            this.httpMessageSigner
        );
    }

    /**
     * Get the {@link AuthorizationContextProvider}
     */
    public AuthorizationContextProvider getAuthorizationContextProvider() {
        return this.authorizationContextProvider;
    }

    /**
     * Get the {@link BokuHttpAuthFilter} to be installed in your web application.
     */
    public BokuHttpAuthFilter getBokuHttpAuthFilter() {
        return new BokuHttpAuthFilter(this.getThreadLocalServletRequestContextHolder(), this.getHttpMessageSigner());
    }

    /**
     * Get the {@link ThreadLocalServletRequestContextHolder}. You should not need to access this manually in most
     * cases.
     */
    public ThreadLocalServletRequestContextHolder getThreadLocalServletRequestContextHolder() {
        return this.threadLocalServletRequestContextHolder;
    }

    /**
     * Get the {@link HttpMessageSigner}
     */
    public HttpMessageSigner getHttpMessageSigner() {
        return this.httpMessageSigner;
    }


    /**
     * For static initialization via {@link BokuHttpAuthFilter} init-params.
     *
     * @param params The filter init params in map form.
     */
    public static synchronized void init(Map<String, String> params) {
        if (staticProperties != null) {
            throw new IllegalStateException("The static " + ServerAuthorizationComponentsFactory.class.getSimpleName() +
                " has already been initialized, either via a prior call to init() or implicitly via a getInstance() call.");
        }
        logger.info("Static factory initialized using init params: {}", params);
        staticProperties = new Properties(System.getProperties());
        for (Map.Entry<String, String> e : params.entrySet()) {
            staticProperties.setProperty(e.getKey(), e.getValue());
        }
        getInstance();
    }

    /**
     * Bootstrap the default instance.
     */
    private static ServerAuthorizationComponentsFactory createDefaultInstance() {
        Properties config = getStaticProperties();

        KeyProvider keyProvider;

        String kpType = config.getProperty(KEYPROVIDER_TYPE_KEY, KEYPROVIDER_TYPE_DEFAULT);
        if (KEYPROVIDER_TYPE_PKCS12.equals(kpType)) {
            String p12File = config.getProperty(KEYPROVIDER_P12_FILE_KEY, KEYPROVIDER_P12_FILE_DEFAULT);
            logger.info("{} set to {}, using KeyProvider backed by file {}...", KEYPROVIDER_TYPE_KEY, kpType, p12File);

            String password = config.getProperty(KEYPROVIDER_P12_PASSWORD_KEY);
            if (password == null) {
                throw new IllegalStateException("No " + KEYPROVIDER_P12_PASSWORD_KEY + " given for PKCS12 file " + p12File);
            }
            try {
                keyProvider = KeystoreKeyProvider.fromPKCS12(p12File, password);
            } catch (FileNotFoundException ex) {
                String cwd;
                try {
                    cwd = new File(".").getCanonicalPath();
                } catch (IOException e2) {
                    cwd = "not-found!";
                }
                throw new IllegalStateException("PKCS12 file " + p12File + " does not exist. Do you need to specify the correct filename with -D" + KEYPROVIDER_P12_FILE_KEY + "? Current working directory: " + cwd);
            } catch (IOException ex) {
                throw new IllegalStateException("IO error loading PKCS12 file " + p12File, ex);
            }

        } else if (KEYPROVIDER_TYPE_CUSTOM.equals(kpType)) {
            String factoryMethod = config.getProperty(KEYPROVIDER_CUSTOM_FACTORY_METHOD_KEY);
            if (factoryMethod == null) {
                throw new IllegalStateException(KEYPROVIDER_TYPE_KEY + "=" + KEYPROVIDER_TYPE_CUSTOM + " requires factory method reference provided via " + KEYPROVIDER_CUSTOM_FACTORY_METHOD_KEY);
            }

            logger.info("{} set to {}, using KeyProvider produced by {} {}...", KEYPROVIDER_TYPE_KEY, kpType, KEYPROVIDER_CUSTOM_FACTORY_METHOD_KEY, factoryMethod);

            String[] parts = factoryMethod.split("\\.");
            String methodName = parts[parts.length - 1];
            String className = String.join(".", Arrays.copyOfRange(parts, 0, parts.length - 1));
            Class<?> cls;
            try {
                cls = Class.forName(className);
            } catch (ClassNotFoundException ex) {
                throw new IllegalStateException("Class " + className + " does not exist");
            }
            Method method;
            try {
                method = cls.getMethod(methodName);
            } catch (NoSuchMethodException ex) {
                throw new IllegalStateException("No public method named " + methodName + " on " + cls);
            }
            if (!Modifier.isStatic(method.getModifiers())) {
                throw new IllegalStateException(factoryMethod + " is not static");
            }
            Object o;
            try {
                o = method.invoke(null);
            } catch (IllegalAccessException | InvocationTargetException ex) {
                throw new IllegalStateException("Failed to invoke " + factoryMethod, ex);
            }
            if (o == null) {
                throw new IllegalStateException(factoryMethod + " returned null");
            }
            if (o instanceof KeyProvider) {
                keyProvider = (KeyProvider)o;
            } else {
                throw new IllegalStateException(o.getClass().getCanonicalName() + " returned by " + factoryMethod + " is not a KeyProvider");
            }

        } else {
            throw new IllegalStateException("Unrecognized " + KEYPROVIDER_TYPE_KEY + " value, '" + kpType + "'");
        }

        return new ServerAuthorizationComponentsFactory(keyProvider);
    }


    private static Properties staticProperties;
    private static synchronized Properties getStaticProperties() {
        if (staticProperties == null) {
            logger.info("Static factory initialized using system properties");
            staticProperties = System.getProperties();
        }
        return staticProperties;
    }
}
