package org.picketlink.identity.federation.web.handlers.saml2;

import javax.servlet.http.HttpServletRequest;

import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.util.StringUtil;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerConfig;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.picketlink.identity.federation.web.core.HTTPContext;

/**
 * Created by pellegatta on 19/07/16.
 */
public class AccessControlAllowResponseHeadersHandler extends BaseSAML2Handler {

	public static final String HEADER_ORIGIN					= "Origin";
	
	public static final String HEADER_ACW_CREDENTIALS 			= "Access-Control-Allow-Credentials";
	public static final String HEADER_ACW_CREDENTIALS_VALUE 	= "true";
	
	public static final String HEADER_ACW_ORIGIN 				= "Access-Control-Allow-Origin";
	
	public static final String HEADER_ACW_HEADERS 				= "Access-Control-Allow-Headers";
	public static final String HEADER_ACW_HEADERS_VALUE 		= "Accept,Authorization, Content-Type, SourceSystem, Timestamp, TransactionId, X-XSRF-TOKEN, x-dtPC";
	
	
	public static final String ALLOWED_ORIGIN_HOSTNAME 			= "ALLOWED_ORIGIN_HOSTNAME";
	public static final String ALLOWED_HEADERS 				    = "ALLOWED_HEADERS";
	
	private String allowedOriginHostname = "";
	private String allowedHeaders = "";
	
	
    @Override
    public void initHandlerConfig(SAML2HandlerConfig handlerConfig) throws ConfigurationException {
    	initAllowedOriginHostname(handlerConfig);
    	super.initHandlerConfig(handlerConfig);
    }
    
	@Override
	public void generateSAMLRequest(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
		injectAccessControlAllowResponseHeaders(request,response);
		super.generateSAMLRequest(request, response);
	}
	
	private void initAllowedOriginHostname(SAML2HandlerConfig handlerConfig) {
		if (handlerConfig.getParameter(ALLOWED_ORIGIN_HOSTNAME) != null) {
			Object allowedOriginHostnameObj = handlerConfig.getParameter(ALLOWED_ORIGIN_HOSTNAME);
			if (allowedOriginHostnameObj instanceof String) {
				allowedOriginHostname = (String)allowedOriginHostnameObj;
			}
		}
		if (handlerConfig.getParameter(ALLOWED_HEADERS) != null) {
			Object allowedHeadersObj = handlerConfig.getParameter(ALLOWED_HEADERS);
			if (allowedHeadersObj instanceof String) {
				allowedHeaders = (String)allowedHeadersObj;
			}
		} else {
			allowedHeaders = HEADER_ACW_HEADERS_VALUE;
		}
	}

	@Override
	public void handleStatusResponseType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
		super.handleStatusResponseType(request, response);
	}
	
	private void injectAccessControlAllowResponseHeaders(SAML2HandlerRequest request, SAML2HandlerResponse response) {
		HttpServletRequest httpRequest = getHttpRequest(request);
		HTTPContext httpContext = (HTTPContext) request.getContext();
		String origin = httpRequest.getHeader(HEADER_ORIGIN);
		if (!StringUtil.isNullOrEmpty(origin) && origin.endsWith(allowedOriginHostname)){
			httpContext.getResponse().addHeader(HEADER_ACW_CREDENTIALS, HEADER_ACW_CREDENTIALS_VALUE);
			httpContext.getResponse().addHeader(HEADER_ACW_HEADERS, allowedHeaders);
			httpContext.getResponse().addHeader(HEADER_ACW_ORIGIN, origin);
		}
	}

	@Override
	public void handleRequestType(SAML2HandlerRequest request, SAML2HandlerResponse response)
			throws ProcessingException {
	}

}
