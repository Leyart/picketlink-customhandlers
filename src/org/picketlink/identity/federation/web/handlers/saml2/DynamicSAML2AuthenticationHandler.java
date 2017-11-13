package org.picketlink.identity.federation.web.handlers.saml2;

import java.io.File;
import java.io.FileInputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.config.federation.AuthPropertyType;
import org.picketlink.config.federation.KeyProviderType;
import org.picketlink.config.federation.SPType;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerChainConfig;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerConfig;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.picketlink.identity.federation.core.util.CoreConfigUtil;
import org.picketlink.identity.federation.core.util.JAXPValidationUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.web.core.HTTPContext;
import org.picketlink.identity.federation.web.filters.IDPFilter;

/**
 * Created by pellegatta on 15/02/16.
 */
public class DynamicSAML2AuthenticationHandler  extends SAML2AuthenticationHandler {

    public static final String DYNAMIC_IDP_URL_SESSION_ATTRIBUTE_NAME = "org.picketlink.federation.dynamic.idp.url";
    
    public static final String PROPERTIES_FILE_PATH = "PROPERTIES_FILE_PATH";
    
    private final Map<String, String> idpRegistry = new HashMap<String, String>();
    private final Map<String, String> spRegistry = new HashMap<String, String>();
    
    private Properties properties = new Properties();

    private TrustKeyManager keyManager;
     
    @Override
    public void initChainConfig(SAML2HandlerChainConfig handlerChainConfig) throws ConfigurationException {
    	super.initChainConfig(handlerChainConfig);
    	if (getProviderconfig().isSupportsSignature()) {
    		initKeyManager();
    	}
    }
    
    @Override
    public void initHandlerConfig(SAML2HandlerConfig handlerConfig) throws ConfigurationException {
    	if (handlerConfig.getParameter(PROPERTIES_FILE_PATH) != null) {
    		String propertiesFilePath = (String)handlerConfig.getParameter(PROPERTIES_FILE_PATH);
    		File propertiesFile = new File(propertiesFilePath);
    		if(propertiesFile.exists() && !propertiesFile.isDirectory()) { 
    		    try {
					properties.load(new FileInputStream(propertiesFile));
					initDynamicEndpoints();
				} catch (Exception e) {
					e.printStackTrace();
				} 
    		}
    	}
    	super.initHandlerConfig(handlerConfig);
    }
    
	private void initDynamicEndpoints() {
		for (String key : properties.stringPropertyNames()) {
			try {
				String value = properties.getProperty(key);
				String[] endpoints = value.split("\\|");
				idpRegistry.put(key, endpoints[0]);
				spRegistry.put(key, endpoints[1]);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	@Override
    public void handleRequestType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
		if (hasServerDynamicEndpoints(request)){
    		setDynamicIdPEndpoint(request,response);
    	}
        super.handleRequestType(request, response);
    }

    @Override
    public void handleStatusResponseType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
    	if (hasServerDynamicEndpoints(request)){
    		setDynamicIdPEndpoint(request,response);
    		setDynamicSPEndpoint(request);
    	}
        super.handleStatusResponseType(request, response);
    }

    @Override
    public void generateSAMLRequest(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
    	if (hasServerDynamicEndpoints(request)){
    		setDynamicIdPEndpoint(request,response);
    		
    	}
    	super.generateSAMLRequest(request, response);
    	if (hasServerDynamicEndpoints(request)){
    		SAMLParser samlParser = new SAMLParser();
            JAXPValidationUtil.checkSchemaValidation(response.getResultingDocument());
            try {
            	AuthnRequestType requestType = (AuthnRequestType) samlParser.parse(DocumentUtil.getNodeAsStream(response.getResultingDocument()));
            	requestType.setAssertionConsumerServiceURL(URI.create(spRegistry.get(getServerName(request))));
            	/*NameIDType issuer = new NameIDType();
                issuer.setValue(spRegistry.get(getServerName(request)));
            	requestType.setIssuer(issuer);*/
            	SAML2Request samlRequest = new SAML2Request();
            	response.setResultingDocument(samlRequest.convert(requestType));
			} catch (Exception e) {
				e.printStackTrace();
			}
    	}
    }

	private void setDynamicSPEndpoint(SAML2HandlerRequest request) {
		ResponseType responseType = (ResponseType) request.getSAML2Object();
		SPType spConfiguration = (SPType) handlerChainConfig.getParameter(GeneralConstants.CONFIGURATION);
		responseType.setDestination(spConfiguration.getServiceURL());
	}


	private void setDynamicIdPEndpoint(SAML2HandlerRequest request, SAML2HandlerResponse response) {
		response.setDestination(resolveIdentityProviderUrl(request, response));
		if (getProviderconfig().isSupportsSignature()) {
			setIssuerPublicKey(request, response);
		}
	}

	private boolean hasServerDynamicEndpoints(SAML2HandlerRequest request) {
		return this.properties!=null && this.properties.containsKey(getServerName(request));
	}

	private String getServerName(SAML2HandlerRequest request){
    	return getHttpRequest(request).getServerName();
    }
    
    /**
     * <p>Resolves the IdP dynamically using the information the request.</p>
     *
     * @param request
     * @param response
     * @return
     */
    private String resolveIdentityProviderUrl(SAML2HandlerRequest request, SAML2HandlerResponse response) {
        HTTPContext httpContext = (HTTPContext) request.getContext();
        HttpServletRequest httpRequest = httpContext.getRequest();
        HttpSession session = httpRequest.getSession(false);
        String idpUrl = null;

        if (session != null) {
            idpUrl = (String) session.getAttribute(DYNAMIC_IDP_URL_SESSION_ATTRIBUTE_NAME);

            // check if the idp was previously selected. if not, we try to use the parameter to select an idp.
            if (idpUrl == null) {
                idpUrl = this.idpRegistry.get(getServerName(request));
                session.setAttribute(DYNAMIC_IDP_URL_SESSION_ATTRIBUTE_NAME, idpUrl);
            }
        }

        // defaults to the idp defined in WEB-INF/picketlink.xml
        if (idpUrl == null) {
            idpUrl = response.getDestination();
        }

        return idpUrl;
    }

    
    /**
     * It dynamically takes the right publicKey, using the dynamic idp hostname.
     * The publicKey is then set in a request option, and will be used by {@link SAML2SignatureValidationHandler}
     * @param request
     * @param response
     */
    private void setIssuerPublicKey(SAML2HandlerRequest request, SAML2HandlerResponse response) {
    	String idpProviderUrl = resolveIdentityProviderUrl(request, response);
    	PublicKey publicKey;
		try {
			publicKey = getIssuerPublicKey(getHttpRequest(request), idpProviderUrl);
			request.addOption(GeneralConstants.SENDER_PUBLIC_KEY, publicKey);
		} catch (ConfigurationException e) {
			logger.error("Unable to set the issuer publicKey, "+e.getMessage());
		} catch (ProcessingException e) {
			logger.error("Unable to set the issuer publicKey, "+e.getMessage());
		}
	}

	/**
	 * logic partially copied from {@link IDPFilter}
	 */
	protected void initKeyManager() {
            KeyProviderType keyProvider = getProviderconfig().getKeyProvider();
            if (keyProvider == null) {
            	throw new RuntimeException(
                        logger.nullValueError("Key Provider is null for context"));
            }
            TrustKeyManager keyManager;
            try {
                keyManager = CoreConfigUtil.getTrustKeyManager(keyProvider);
                List<AuthPropertyType> authProperties = CoreConfigUtil.getKeyProviderProperties(keyProvider);
                keyManager.setAuthProperties(authProperties);
                keyManager.setValidatingAlias(keyProvider.getValidatingAlias());
                // Special case when you need X509Data in SignedInfo
                if (authProperties != null) {
                    for (AuthPropertyType authPropertyType : authProperties) {
                        String key = authPropertyType.getKey();
                        if (GeneralConstants.X509CERTIFICATE.equals(key)) {
                            // we need X509Certificate in SignedInfo. The value is the alias name
                            keyManager.addAdditionalOption(GeneralConstants.X509CERTIFICATE, authPropertyType.getValue());
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                logger.trustKeyManagerCreationError(e);
                throw new RuntimeException(e.getLocalizedMessage());
            }
            XMLSignatureUtil.setCanonicalizationMethodType(getProviderconfig().getCanonicalizationMethod());
            this.keyManager = keyManager;
    }
	
	/**
	 * logic partially copied from {@link IDPFilter}
	 */
	private PublicKey getIssuerPublicKey(HttpServletRequest request, String identityProviderUrl)
			throws ConfigurationException, ProcessingException {
		PublicKey issuerPublicKey = null;
		String issuerHost = "";
		try {
			issuerHost = new URL(identityProviderUrl).getHost();
		} catch (MalformedURLException e) {
			logger.warn("Token issuer is not a valid URL: " + identityProviderUrl);
			issuerHost = identityProviderUrl;
		}
		try {
			issuerPublicKey = CoreConfigUtil.getValidatingKey(keyManager, issuerHost);
		} catch (IllegalStateException ise) {
			logger.warn("Token issuer is not found for: " + identityProviderUrl);
		}

		if (issuerPublicKey == null) {
			issuerHost = request.getRemoteAddr();
			issuerPublicKey = CoreConfigUtil.getValidatingKey(keyManager, issuerHost);
		}
		logger.info("Using Validating Alias=" + issuerHost + " to check signatures.");
		return issuerPublicKey;
	}
}


