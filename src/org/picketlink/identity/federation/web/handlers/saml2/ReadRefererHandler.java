package org.picketlink.identity.federation.web.handlers.saml2;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.util.StringUtil;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;

/**
 * Created by pellegatta on 06/05/16.
 */
public class ReadRefererHandler extends BaseSAML2Handler {

	public static final String ORIGINAL_REFERER = "OriginalReferer";
	public static final String REFERER = "Referer";
	
	@Override
	public void generateSAMLRequest(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
		saveOriginalRefererToSession(request);
		super.generateSAMLRequest(request, response);
	}
	
	@Override
	public void handleStatusResponseType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
		super.handleStatusResponseType(request, response);
	}
	
	private void saveOriginalRefererToSession(SAML2HandlerRequest request) {
		HttpServletRequest httpRequest = getHttpRequest(request);
		String referer = httpRequest.getHeader(REFERER);
		if (!StringUtil.isNullOrEmpty(referer)) {
			HttpSession session = httpRequest.getSession(false);
			session.setAttribute(ORIGINAL_REFERER, referer);
		}
	}

	@Override
	public void handleRequestType(SAML2HandlerRequest request, SAML2HandlerResponse response)
			throws ProcessingException {
	}

}
